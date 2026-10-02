// Package assess evaluates IPsec security controls (C01–C13), computes
// score/coverage/risk, generates findings, and builds the threat matrix.
package assess

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/SIH-2026/trace/internal/evidence"
	"github.com/SIH-2026/trace/internal/iana"
	"github.com/SIH-2026/trace/internal/ike"
	"github.com/SIH-2026/trace/internal/ipsec"
	"github.com/SIH-2026/trace/internal/policy"
)

// ControlStatus is the result of evaluating a control.
type ControlStatus string

const (
	StatusPass    ControlStatus = "PASS"
	StatusFail    ControlStatus = "FAIL"
	StatusUnknown ControlStatus = "UNKNOWN"
	StatusNA      ControlStatus = "N/A"
)

// Control is the evaluation result for one security control.
type Control struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Status      ControlStatus   `json:"status"`
	Severity    policy.Severity `json:"severity,omitempty"`
	Weight      int             `json:"weight"`
	Explanation string          `json:"explanation"`
	EvidenceIDs []string        `json:"evidence_ids,omitempty"`
	RFC         string          `json:"rfc,omitempty"`
	Fix         string          `json:"fix,omitempty"`
}

// Finding is a specific issue found during assessment.
type Finding struct {
	ID          string          `json:"id"`
	ControlID   string          `json:"control_id"`
	Severity    policy.Severity `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	WhyMatters  string          `json:"why_matters"`
	EvidenceIDs []string        `json:"evidence_ids"`
	Packets     []int           `json:"packets,omitempty"`
	FixConfig   string          `json:"fix_config,omitempty"`
	FixText     string          `json:"fix_text,omitempty"`
	Status      string          `json:"status"` // CONFIRMED or POSSIBLE
}

// ThreatStatus indicates the mitigation level of a threat.
type ThreatStatus string

const (
	ThreatExposed    ThreatStatus = "Exposed"
	ThreatUnverified ThreatStatus = "Unverified"
	ThreatMitigated  ThreatStatus = "Mitigated"
)

// Threat represents a row in the threat matrix.
type Threat struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Status     ThreatStatus `json:"status"`
	Controls   []string     `json:"controls"`
	Likelihood string       `json:"likelihood"`
	Impact     string       `json:"impact"`
	ATTACKIDs  []string     `json:"attack_ids,omitempty"`
}

// RiskLevel categorises the overall risk.
type RiskLevel string

const (
	RiskLow          RiskLevel = "LOW"
	RiskModerate     RiskLevel = "MODERATE"
	RiskHigh         RiskLevel = "HIGH"
	RiskCritical     RiskLevel = "CRITICAL"
	RiskUndetermined RiskLevel = "UNDETERMINED"
)

// Headline is the summary assessment.
type Headline struct {
	Label      string    `json:"label"`
	Score      float64   `json:"score"`
	Coverage   float64   `json:"coverage"`
	Confidence float64   `json:"confidence"`
	LowerBound float64   `json:"lower_bound"`
	UpperBound float64   `json:"upper_bound"`
	Risk       float64   `json:"risk"`
	RiskLevel  RiskLevel `json:"risk_level"`
	Grade      string    `json:"grade,omitempty"`
}

// Assessment is the complete evaluation result.
type Assessment struct {
	Headline Headline  `json:"headline"`
	Controls []Control `json:"controls"`
	Findings []Finding `json:"findings"`
	Threats  []Threat  `json:"threats"`
	PolicyID string    `json:"policy_id"`
	Profile  string    `json:"profile"`
}

// controlWeights defines the weight of each control.
var controlWeights = map[string]int{
	"C01": 10, "C02": 25, "C03": 15, "C04": 20,
	"C05": 15, "C06": 10, "C07": 20, "C08": 15,
	"C09": 15, "C10": 10, "C11": 10, "C12": 5, "C13": 5,
}

// Assess runs the full assessment on IKE SAs and ESP/AH inventory.
func Assess(saTable *ike.SATable, espInv *ipsec.Inventory, ledger *evidence.Ledger, prof policy.Profile) *Assessment {
	a := &Assessment{
		PolicyID: policy.PolicyVersion,
		Profile:  prof.ID,
	}

	// Evaluate controls across all SAs.
	var allControls [][]Control

	for _, sa := range saTable.SAs {
		resource := evidence.Resource{Type: "ike_sa", ID: fmt.Sprintf("%016x", sa.InitiatorSPI)}
		controls := evaluateControls(sa, espInv, ledger, prof, resource)
		allControls = append(allControls, controls)
	}

	// If no SAs, produce UNKNOWN controls.
	if len(allControls) == 0 {
		a.Controls = defaultControls()
	} else {
		// Aggregate: worst status per control across SAs.
		a.Controls = aggregateControls(allControls)
	}

	// Compute score, coverage, and risk.
	a.Headline = computeHeadline(a.Controls)

	// Generate findings from failed controls.
	a.Findings = generateFindings(a.Controls)

	// Build threat matrix.
	a.Threats = buildThreatMatrix(a.Controls)

	return a
}

func evaluateControls(sa *ike.SA, espInv *ipsec.Inventory, ledger *evidence.Ledger, prof policy.Profile, resource evidence.Resource) []Control {
	controls := make([]Control, 0, 13)

	// C01: IKE Version
	controls = append(controls, evalC01(sa, ledger, resource))
	// C02: IKE Encryption
	controls = append(controls, evalC02(sa, ledger, resource, prof))
	// C03: Integrity and PRF
	controls = append(controls, evalC03(sa, ledger, resource))
	// C04: DH Group
	controls = append(controls, evalC04(sa, ledger, resource, prof))
	// C05: Weak Offers
	controls = append(controls, evalC05(sa, ledger, resource, prof))
	// C06: Negotiation Consistency
	controls = append(controls, evalC06(sa, ledger, resource))
	// C07: Peer Authentication
	controls = append(controls, evalC07(sa, ledger, resource))
	// C08: Child Suite (gateway only)
	controls = append(controls, evalC08(sa, ledger, resource))
	// C09: PFS (gateway only)
	controls = append(controls, evalC09(sa, ledger, resource))
	// C10: Lifetimes
	controls = append(controls, evalC10(sa, ledger, resource, prof))
	// C11: Replay Window
	controls = append(controls, evalC11(sa, ledger, resource, prof))
	// C12: Identity Exposure
	controls = append(controls, evalC12(sa, ledger, resource))
	// C13: Protocol Hygiene
	controls = append(controls, evalC13(sa, ledger, resource))

	return controls
}

func evalC01(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C01", Name: "IKE Version", Weight: controlWeights["C01"],
		RFC: "RFC 7296",
	}

	eid := ledger.Add(evidence.Evidence{
		Property: "ike.version",
		Value:    evidence.Value{Raw: fmt.Sprintf("IKEv%d", sa.Version)},
		Status:   evidence.StatusObserved,
		Resource: res,
		Source:   evidence.Source{Kind: evidence.SourcePacket, Packets: []int{sa.FirstPkt}},
	})
	c.EvidenceIDs = []string{eid}

	switch sa.Version {
	case 2:
		c.Status = StatusPass
		c.Explanation = "IKEv2 observed"
	case 1:
		c.Status = StatusFail
		if sa.V1Aggressive {
			c.Severity = policy.SevHigh
			c.Explanation = "IKEv1 Aggressive Mode observed — identity may be exposed"
		} else {
			c.Severity = policy.SevMedium
			c.Explanation = "IKEv1 observed — consider migrating to IKEv2"
		}
	default:
		c.Status = StatusUnknown
		c.Explanation = fmt.Sprintf("Unknown IKE version %d", sa.Version)
	}
	return c
}

func evalC02(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource, prof policy.Profile) Control {
	c := Control{
		ID: "C02", Name: "IKE Encryption", Weight: controlWeights["C02"],
		RFC: "RFC 8221", Fix: policy.FixTemplate("C02"),
	}

	var encName string
	var keyBits int
	var aead bool

	if sa.Version == 2 && sa.Negotiation.Selected != nil {
		for _, tr := range sa.Negotiation.Selected.Transforms {
			if tr.Type == iana.TypeEncryption {
				encName = tr.Name
				keyBits = tr.KeyBits
				aead = tr.AEAD
				break
			}
		}
	} else if sa.Version == 1 {
		encName = sa.V1Encryption
		keyBits = int(sa.V1KeyBits)
	}

	if encName == "" {
		c.Status = StatusUnknown
		c.Explanation = "IKE encryption algorithm not observed"
		return c
	}

	eid := ledger.Add(evidence.Evidence{
		Property: "ike.encryption",
		Value:    evidence.Value{Algorithm: encName, KeyBits: keyBits},
		Status:   evidence.StatusObserved,
		Resource: res,
		Source:   evidence.Source{Kind: evidence.SourcePacket, Packets: []int{sa.FirstPkt}},
	})
	c.EvidenceIDs = []string{eid}

	class := policy.ClassifyEncryption(encName, keyBits, aead)
	if class == policy.ClassProhibited || class == policy.ClassLegacy {
		c.Status = StatusFail
		c.Severity = policy.SeverityForClass(class)
		c.Explanation = fmt.Sprintf("%s (%d-bit) is %s", encName, keyBits, class)
	} else {
		c.Status = StatusPass
		c.Explanation = fmt.Sprintf("%s (%d-bit) is %s", encName, keyBits, class)
	}
	return c
}

func evalC03(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C03", Name: "Integrity and PRF", Weight: controlWeights["C03"],
		RFC: "RFC 8221",
	}

	if sa.Version == 2 && sa.Negotiation.Selected != nil {
		var isAEAD bool
		var integName, prfName string
		for _, tr := range sa.Negotiation.Selected.Transforms {
			switch tr.Type {
			case iana.TypeEncryption:
				isAEAD = tr.AEAD
			case iana.TypeIntegrity:
				integName = tr.Name
			case iana.TypePRF:
				prfName = tr.Name
			}
		}

		if isAEAD {
			c.Status = StatusPass
			c.Explanation = "AEAD cipher provides built-in integrity"
			if prfName != "" {
				eid := ledger.Add(evidence.Evidence{
					Property: "ike.prf",
					Value:    evidence.Value{Algorithm: prfName},
					Status:   evidence.StatusObserved,
					Resource: res,
					Source:   evidence.Source{Kind: evidence.SourcePacket},
				})
				c.EvidenceIDs = append(c.EvidenceIDs, eid)
			}
			return c
		}

		if integName != "" {
			class := policy.ClassifyIntegrity(integName)
			eid := ledger.Add(evidence.Evidence{
				Property: "ike.integrity",
				Value:    evidence.Value{Algorithm: integName},
				Status:   evidence.StatusObserved,
				Resource: res,
				Source:   evidence.Source{Kind: evidence.SourcePacket},
			})
			c.EvidenceIDs = append(c.EvidenceIDs, eid)

			if class == policy.ClassProhibited || class == policy.ClassLegacy {
				c.Status = StatusFail
				c.Severity = policy.SeverityForClass(class)
				c.Explanation = fmt.Sprintf("%s is %s", integName, class)
			} else {
				c.Status = StatusPass
				c.Explanation = fmt.Sprintf("%s is %s", integName, class)
			}
			return c
		}
	} else if sa.Version == 1 && sa.V1Hash != "" {
		eid := ledger.Add(evidence.Evidence{
			Property: "ike.hash",
			Value:    evidence.Value{Algorithm: sa.V1Hash},
			Status:   evidence.StatusObserved,
			Resource: res,
			Source:   evidence.Source{Kind: evidence.SourcePacket},
		})
		c.EvidenceIDs = []string{eid}

		class := policy.ClassifyIntegrity("HMAC-" + sa.V1Hash + "-96")
		if class == policy.ClassProhibited {
			c.Status = StatusFail
			c.Severity = policy.SevHigh
			c.Explanation = fmt.Sprintf("IKEv1 hash %s is prohibited", sa.V1Hash)
		} else {
			c.Status = StatusPass
			c.Explanation = fmt.Sprintf("IKEv1 hash %s", sa.V1Hash)
		}
		return c
	}

	c.Status = StatusUnknown
	c.Explanation = "Integrity/PRF algorithm not observed"
	return c
}

func evalC04(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource, prof policy.Profile) Control {
	c := Control{
		ID: "C04", Name: "DH Group", Weight: controlWeights["C04"],
		RFC: "RFC 8247", Fix: policy.FixTemplate("C04"),
	}

	var groupID uint16
	if sa.Version == 2 {
		if sa.Negotiation.KEGroup > 0 {
			groupID = sa.Negotiation.KEGroup
		} else if sa.Negotiation.SelectedDH > 0 {
			groupID = sa.Negotiation.SelectedDH
		}
	} else if sa.Version == 1 {
		groupID = sa.V1Group
	}

	if groupID == 0 {
		c.Status = StatusUnknown
		c.Explanation = "DH group not observed"
		return c
	}

	dh, _ := iana.LookupDH(groupID)
	eid := ledger.Add(evidence.Evidence{
		Property: "ike.dh_group",
		Value:    evidence.Value{Algorithm: dh.Name, KeyBits: dh.KeyBits},
		Status:   evidence.StatusObserved,
		Resource: res,
		Source:   evidence.Source{Kind: evidence.SourcePacket},
	})
	c.EvidenceIDs = []string{eid}

	class := policy.ClassifyDH(groupID, dh.KeyBits)
	if class == policy.ClassProhibited || class == policy.ClassLegacy {
		c.Status = StatusFail
		c.Severity = policy.SeverityForClass(class)
		c.Explanation = fmt.Sprintf("%s (%d-bit) is %s", dh.Name, dh.KeyBits, class)
	} else {
		c.Status = StatusPass
		c.Explanation = fmt.Sprintf("%s (%d-bit) is %s", dh.Name, dh.KeyBits, class)
	}
	return c
}

func evalC05(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource, prof policy.Profile) Control {
	c := Control{
		ID: "C05", Name: "Weak Offers", Weight: controlWeights["C05"],
		RFC: "RFC 8221", Fix: policy.FixTemplate("C05"),
	}

	if len(sa.Negotiation.Offered) == 0 {
		c.Status = StatusUnknown
		c.Explanation = "Offered proposals not observed"
		return c
	}

	var weakOffers []string
	for _, prop := range sa.Negotiation.Offered {
		for _, tr := range prop.Transforms {
			if tr.Type == iana.TypeEncryption {
				class := policy.ClassifyEncryption(tr.Name, tr.KeyBits, tr.AEAD)
				if class == policy.ClassLegacy || class == policy.ClassProhibited {
					weakOffers = append(weakOffers, tr.String())
				}
			}
			if tr.Type == iana.TypeDH {
				class := policy.ClassifyDH(tr.ID, tr.KeyBits)
				if class == policy.ClassLegacy || class == policy.ClassProhibited {
					weakOffers = append(weakOffers, tr.String())
				}
			}
		}
	}

	if len(weakOffers) > 0 {
		c.Status = StatusFail
		c.Severity = policy.SevMedium
		eid := ledger.Add(evidence.Evidence{
			Property: "ike.weak_offers",
			Value:    evidence.Value{Raw: strings.Join(weakOffers, ", ")},
			Status:   evidence.StatusObserved,
			Resource: res,
			Source:   evidence.Source{Kind: evidence.SourcePacket},
		})
		c.EvidenceIDs = []string{eid}
		c.Explanation = fmt.Sprintf("Weak algorithms offered: %s", strings.Join(weakOffers, ", "))
	} else {
		c.Status = StatusPass
		c.Explanation = "No weak algorithms in offered proposals"
	}
	return c
}

func evalC06(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C06", Name: "Negotiation Consistency", Weight: controlWeights["C06"],
		RFC: "RFC 7296",
	}

	if sa.Negotiation.Selected == nil || len(sa.Negotiation.Offered) == 0 {
		c.Status = StatusUnknown
		c.Explanation = "Negotiation not fully observed"
		return c
	}

	if sa.Negotiation.Consistent {
		c.Status = StatusPass
		c.Explanation = "Selected proposal matches an offered proposal"
	} else {
		c.Status = StatusFail
		c.Severity = policy.SevHigh
		c.Explanation = "Selected proposal not found in offered proposals — possible inconsistency"
	}

	// Check KE group vs selected DH.
	if sa.Negotiation.KEGroup > 0 && sa.Negotiation.SelectedDH > 0 {
		if sa.Negotiation.KEGroup != sa.Negotiation.SelectedDH {
			c.Status = StatusFail
			c.Severity = policy.SevHigh
			c.Explanation += fmt.Sprintf("; KE group %d ≠ selected DH %d", sa.Negotiation.KEGroup, sa.Negotiation.SelectedDH)
		}
	}

	return c
}

func evalC07(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C07", Name: "Peer Authentication", Weight: controlWeights["C07"],
		RFC: "RFC 7296", Fix: policy.FixTemplate("C07"),
	}

	if sa.Version == 1 {
		if sa.V1AuthMethod != "" {
			eid := ledger.Add(evidence.Evidence{
				Property: "ike.auth_method",
				Value:    evidence.Value{Raw: sa.V1AuthMethod},
				Status:   evidence.StatusObserved,
				Resource: res,
				Source:   evidence.Source{Kind: evidence.SourcePacket},
			})
			c.EvidenceIDs = []string{eid}

			if sa.V1Aggressive && sa.V1AuthMethod == "PSK" {
				c.Status = StatusFail
				c.Severity = policy.SevHigh
				c.Explanation = "Aggressive Mode with PSK — identity exposed, offline attack possible"
			} else if sa.V1AuthMethod == "RSA-Sig" || sa.V1AuthMethod == "ECDSA-256" || sa.V1AuthMethod == "ECDSA-384" {
				c.Status = StatusPass
				c.Explanation = fmt.Sprintf("IKEv1 %s authentication", sa.V1AuthMethod)
			} else {
				c.Status = StatusUnknown
				c.Explanation = fmt.Sprintf("IKEv1 %s — strength unclear without gateway data", sa.V1AuthMethod)
			}
			return c
		}
	}

	if sa.HasCert {
		c.Status = StatusPass
		c.Explanation = "Certificate-based authentication observed"
		return c
	}

	c.Status = StatusUnknown
	c.Explanation = "Authentication method not visible from capture — need gateway facts"
	return c
}

func evalC08(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	return Control{
		ID: "C08", Name: "Child SA Suite", Weight: controlWeights["C08"],
		Status: StatusUnknown, Explanation: "Child SA suite requires gateway configuration data",
		RFC: "RFC 8221",
	}
}

func evalC09(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	return Control{
		ID: "C09", Name: "Perfect Forward Secrecy", Weight: controlWeights["C09"],
		Status: StatusUnknown, Explanation: "PFS status requires gateway configuration data",
		RFC: "RFC 8221",
	}
}

func evalC10(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource, prof policy.Profile) Control {
	c := Control{
		ID: "C10", Name: "SA Lifetimes", Weight: controlWeights["C10"],
		RFC: "RFC 7296", Fix: policy.FixTemplate("C10"),
	}

	if sa.Version == 1 && sa.V1LifeSecs > 0 {
		eid := ledger.Add(evidence.Evidence{
			Property: "ike.lifetime_seconds",
			Value:    evidence.Value{Uint: uint64(sa.V1LifeSecs)},
			Status:   evidence.StatusObserved,
			Resource: res,
			Source:   evidence.Source{Kind: evidence.SourcePacket},
		})
		c.EvidenceIDs = []string{eid}

		if sa.V1LifeSecs > prof.MaxIKELifetime {
			c.Status = StatusFail
			c.Severity = policy.SevMedium
			c.Explanation = fmt.Sprintf("IKE SA lifetime %d s exceeds maximum %d s", sa.V1LifeSecs, prof.MaxIKELifetime)
		} else {
			c.Status = StatusPass
			c.Explanation = fmt.Sprintf("IKE SA lifetime %d s within limit", sa.V1LifeSecs)
		}
		return c
	}

	c.Status = StatusUnknown
	c.Explanation = "SA lifetime not observed — need gateway data or rekey events"
	return c
}

func evalC11(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource, prof policy.Profile) Control {
	return Control{
		ID: "C11", Name: "Anti-Replay Window", Weight: controlWeights["C11"],
		Status: StatusUnknown, Explanation: "Replay window requires gateway configuration data",
		RFC: "RFC 4303", Fix: policy.FixTemplate("C11"),
	}
}

func evalC12(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C12", Name: "Identity Exposure", Weight: controlWeights["C12"],
		RFC: "RFC 7296",
	}

	if sa.V1IdentityExposed {
		c.Status = StatusFail
		c.Severity = policy.SevMedium
		c.Explanation = "IKEv1 Aggressive Mode exposes identity in cleartext"
		eid := ledger.Add(evidence.Evidence{
			Property: "ike.identity_exposed",
			Value:    evidence.Value{Bool: boolPtr(true)},
			Status:   evidence.StatusObserved,
			Resource: res,
			Source:   evidence.Source{Kind: evidence.SourcePacket},
		})
		c.EvidenceIDs = []string{eid}
	} else if len(sa.Exchanges) > 0 {
		c.Status = StatusPass
		c.Explanation = "No cleartext identity exposure observed"
	} else {
		c.Status = StatusUnknown
		c.Explanation = "No IKE exchanges observed"
	}
	return c
}

func evalC13(sa *ike.SA, ledger *evidence.Ledger, res evidence.Resource) Control {
	c := Control{
		ID: "C13", Name: "Protocol Hygiene", Weight: controlWeights["C13"],
		RFC: "RFC 7296",
	}

	issues := 0
	var details []string

	if sa.MalformedCount > 0 {
		issues++
		details = append(details, fmt.Sprintf("%d malformed messages", sa.MalformedCount))
	}
	if sa.DuplicateCount > 10 {
		issues++
		details = append(details, fmt.Sprintf("%d retransmissions (storm)", sa.DuplicateCount))
	}

	if issues > 0 {
		c.Status = StatusFail
		c.Severity = policy.SevLow
		c.Explanation = strings.Join(details, "; ")
	} else if len(sa.Exchanges) > 0 {
		c.Status = StatusPass
		c.Explanation = "No protocol hygiene issues"
	} else {
		c.Status = StatusNA
		c.Explanation = "No exchanges to evaluate"
	}
	return c
}

func defaultControls() []Control {
	names := map[string]string{
		"C01": "IKE Version", "C02": "IKE Encryption", "C03": "Integrity and PRF",
		"C04": "DH Group", "C05": "Weak Offers", "C06": "Negotiation Consistency",
		"C07": "Peer Authentication", "C08": "Child SA Suite", "C09": "Perfect Forward Secrecy",
		"C10": "SA Lifetimes", "C11": "Anti-Replay Window", "C12": "Identity Exposure",
		"C13": "Protocol Hygiene",
	}

	controls := make([]Control, 0, 13)
	for i := 1; i <= 13; i++ {
		id := fmt.Sprintf("C%02d", i)
		controls = append(controls, Control{
			ID:          id,
			Name:        names[id],
			Status:      StatusUnknown,
			Weight:      controlWeights[id],
			Explanation: "No IKE traffic observed",
		})
	}
	return controls
}

func aggregateControls(allControls [][]Control) []Control {
	if len(allControls) == 1 {
		return allControls[0]
	}

	// Use the first SA's controls as a template, then take the worst per control.
	result := make([]Control, len(allControls[0]))
	copy(result, allControls[0])

	statusOrder := map[ControlStatus]int{
		StatusFail: 4, StatusUnknown: 2, StatusPass: 1, StatusNA: 0,
	}

	for i := range result {
		for _, saControls := range allControls[1:] {
			if i < len(saControls) && statusOrder[saControls[i].Status] > statusOrder[result[i].Status] {
				result[i] = saControls[i]
			}
		}
	}
	return result
}

func computeHeadline(controls []Control) Headline {
	var totalWeight, passWeight, evalWeight int
	var confSum float64
	var confCount int
	hasCritical := false

	for _, c := range controls {
		if c.Status == StatusNA {
			continue
		}
		totalWeight += c.Weight

		switch c.Status {
		case StatusPass:
			evalWeight += c.Weight
			passWeight += c.Weight
		case StatusFail:
			evalWeight += c.Weight
			if c.Severity == policy.SevCritical {
				hasCritical = true
			}
		case StatusUnknown:
			// Not evaluated — doesn't count.
		}
	}

	h := Headline{}

	if totalWeight == 0 {
		h.Label = "Insufficient evidence"
		h.RiskLevel = RiskUndetermined
		return h
	}

	if evalWeight > 0 {
		h.Score = 100.0 * float64(passWeight) / float64(evalWeight)
	}
	h.Coverage = 100.0 * float64(evalWeight) / float64(totalWeight)

	// Confidence from evidence.
	for _, c := range controls {
		if c.Status == StatusPass || c.Status == StatusFail {
			confSum += 1.0
			confCount++
		}
	}
	if confCount > 0 {
		h.Confidence = confSum / float64(confCount)
	}

	// Bounds.
	h.LowerBound = 100.0 * float64(passWeight) / float64(totalWeight)
	h.UpperBound = 100.0 * float64(passWeight+totalWeight-evalWeight) / float64(totalWeight)

	// CRITICAL cap.
	if hasCritical && h.Score > 40 {
		h.Score = 40
	}

	// Risk.
	h.Risk = 100 - h.LowerBound
	switch {
	case h.Coverage < 40:
		h.RiskLevel = RiskUndetermined
	case h.Risk <= 20:
		h.RiskLevel = RiskLow
	case h.Risk <= 45:
		h.RiskLevel = RiskModerate
	case h.Risk <= 70:
		h.RiskLevel = RiskHigh
	default:
		h.RiskLevel = RiskCritical
	}

	// Grade / label.
	switch {
	case h.Coverage >= 70:
		h.Grade = letterGrade(h.Score)
		h.Label = fmt.Sprintf("Grade %s", h.Grade)
	case h.Coverage >= 40:
		h.Label = fmt.Sprintf("Provisional %.0f (coverage %.0f%%)", h.Score, h.Coverage)
	default:
		h.Label = fmt.Sprintf("Insufficient evidence (bounds %.0f–%.0f)", h.LowerBound, h.UpperBound)
	}

	return h
}

func letterGrade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func generateFindings(controls []Control) []Finding {
	var findings []Finding
	for _, c := range controls {
		if c.Status != StatusFail {
			continue
		}
		f := Finding{
			ID:          fmt.Sprintf("TRACE-%s", c.ID),
			ControlID:   c.ID,
			Severity:    c.Severity,
			Title:       c.Name + " — " + c.Explanation,
			WhyMatters:  c.RFC,
			EvidenceIDs: c.EvidenceIDs,
			Status:      "CONFIRMED",
		}
		if c.Fix != "" {
			f.FixConfig = c.Fix
			f.FixText = "Update strongSwan swanctl.conf: " + c.Fix
		}
		findings = append(findings, f)
	}

	// Sort by severity.
	sevOrder := map[policy.Severity]int{
		policy.SevCritical: 4, policy.SevHigh: 3, policy.SevMedium: 2,
		policy.SevLow: 1, policy.SevInfo: 0,
	}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] > sevOrder[findings[j].Severity]
	})

	return findings
}

func buildThreatMatrix(controls []Control) []Threat {
	controlMap := make(map[string]ControlStatus)
	for _, c := range controls {
		controlMap[c.ID] = c.Status
	}

	threats := []Threat{
		{
			ID: "T1", Name: "Downgrade Attack",
			Controls: []string{"C05", "C06"}, Likelihood: "Medium", Impact: "High",
			ATTACKIDs: []string{"T1557"},
		},
		{
			ID: "T2", Name: "Passive Decryption (Weak Cipher)",
			Controls: []string{"C02", "C08"}, Likelihood: "Low", Impact: "Critical",
			ATTACKIDs: []string{"T1040"},
		},
		{
			ID: "T3", Name: "Loss of Forward Secrecy",
			Controls: []string{"C04", "C09"}, Likelihood: "Low", Impact: "High",
			ATTACKIDs: []string{"T1600.001"},
		},
		{
			ID: "T4", Name: "Replay Attack",
			Controls: []string{"C11"}, Likelihood: "Low", Impact: "Medium",
		},
		{
			ID: "T5", Name: "Identity Exposure",
			Controls: []string{"C12"}, Likelihood: "Medium", Impact: "Medium",
			ATTACKIDs: []string{"T1040"},
		},
		{
			ID: "T6", Name: "Weak Authentication",
			Controls: []string{"C07"}, Likelihood: "Medium", Impact: "Critical",
			ATTACKIDs: []string{"T1557"},
		},
		{
			ID: "T7", Name: "Key Exposure from Long Lifetimes",
			Controls: []string{"C10"}, Likelihood: "Low", Impact: "High",
			ATTACKIDs: []string{"T1600"},
		},
	}

	for i, threat := range threats {
		threats[i].Status = deriveThreatStatus(threat.Controls, controlMap)
	}

	return threats
}

func deriveThreatStatus(controlIDs []string, controlMap map[string]ControlStatus) ThreatStatus {
	anyFail := false
	anyUnknown := false
	allPass := true

	for _, id := range controlIDs {
		s, ok := controlMap[id]
		if !ok {
			allPass = false
			anyUnknown = true
			continue
		}
		switch s {
		case StatusFail:
			anyFail = true
			allPass = false
		case StatusUnknown:
			anyUnknown = true
			allPass = false
		case StatusNA:
			// doesn't affect
		case StatusPass:
			// good
		}
	}

	if anyFail {
		return ThreatExposed
	}
	if anyUnknown {
		return ThreatUnverified
	}
	if allPass {
		return ThreatMitigated
	}
	return ThreatUnverified
}

func boolPtr(b bool) *bool { return &b }

// Round rounds a float to n decimal places.
func Round(f float64, n int) float64 {
	p := math.Pow(10, float64(n))
	return math.Round(f*p) / p
}
