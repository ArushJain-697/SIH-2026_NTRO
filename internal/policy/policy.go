// Package policy provides versioned security baselines and profiles for
// evaluating IPsec configurations against recommended standards.
//
// References: RFC 8221, RFC 8247, NIST SP 800-77r1.
package policy

// PolicyVersion is the current baseline version.
const PolicyVersion = "baseline-v1"

// AlgorithmClass categorises transforms by security level.
type AlgorithmClass string

const (
	ClassRecommended AlgorithmClass = "Recommended"
	ClassAcceptable  AlgorithmClass = "Acceptable"
	ClassLegacy      AlgorithmClass = "Legacy"
	ClassProhibited  AlgorithmClass = "Prohibited"
)

// Severity levels for policy violations.
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

// Profile is a named policy profile.
type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Strictness: algorithms below this class are flagged.
	MinClass AlgorithmClass `json:"min_class"`
	// Lifetime limits in seconds.
	MaxIKELifetime   uint32 `json:"max_ike_lifetime"`
	MaxChildLifetime uint32 `json:"max_child_lifetime"`
	// Minimum DH group ID for ECP groups.
	MinDHGroup uint16 `json:"min_dh_group"`
	// Minimum replay window.
	MinReplayWindow int `json:"min_replay_window"`
}

// DefaultProfile is the standard TRACE assessment profile.
var DefaultProfile = Profile{
	ID:               "trace-default",
	Name:             "TRACE Default",
	Description:      "Standard assessment based on RFC 8221, RFC 8247",
	MinClass:         ClassAcceptable,
	MaxIKELifetime:   86400, // 24 hours
	MaxChildLifetime: 28800, // 8 hours
	MinDHGroup:       14,    // MODP-2048 minimum
	MinReplayWindow:  64,
}

// StrictProfile is a stricter assessment profile.
var StrictProfile = Profile{
	ID:               "strict",
	Name:             "Strict",
	Description:      "Stricter assessment: no CBC for new deployments, DH >= 19, shorter lifetimes",
	MinClass:         ClassRecommended,
	MaxIKELifetime:   28800, // 8 hours
	MaxChildLifetime: 3600,  // 1 hour
	MinDHGroup:       19,    // ECP-256 minimum
	MinReplayWindow:  64,
}

// GetProfile returns the named profile.
func GetProfile(name string) Profile {
	switch name {
	case "strict":
		return StrictProfile
	default:
		return DefaultProfile
	}
}

// ClassifyEncryption returns the class for an encryption algorithm.
func ClassifyEncryption(name string, keyBits int, aead bool) AlgorithmClass {
	switch {
	case name == "NULL":
		return ClassProhibited
	case name == "DES" || name == "DES-IV64" || name == "DES-IV32":
		return ClassProhibited
	case name == "3DES":
		return ClassLegacy
	case name == "Blowfish" || name == "CAST" || name == "IDEA" || name == "3IDEA" || name == "RC5":
		return ClassProhibited
	case aead && keyBits >= 256:
		return ClassRecommended
	case aead && keyBits >= 128:
		return ClassAcceptable
	case keyBits >= 256:
		return ClassAcceptable
	case keyBits >= 128:
		return ClassAcceptable
	default:
		return ClassLegacy
	}
}

// ClassifyDH returns the class for a DH group.
func ClassifyDH(groupID uint16, keyBits int) AlgorithmClass {
	switch {
	case groupID == 0:
		return ClassProhibited // No DH
	case keyBits >= 384: // ECP-384 or MODP-8192+
		return ClassRecommended
	case keyBits >= 256: // ECP-256 or MODP-4096+
		return ClassRecommended
	case keyBits >= 2048:
		return ClassAcceptable
	case keyBits >= 1536:
		return ClassLegacy
	default:
		return ClassProhibited
	}
}

// ClassifyIntegrity returns the class for an integrity algorithm.
func ClassifyIntegrity(name string) AlgorithmClass {
	switch {
	case name == "NONE":
		return ClassProhibited
	case name == "HMAC-MD5-96" || name == "HMAC-MD5-128" || name == "KPDK-MD5" || name == "DES-MAC":
		return ClassProhibited
	case name == "HMAC-SHA1-96" || name == "HMAC-SHA1-160":
		return ClassLegacy
	case name == "AES-XCBC-96" || name == "AES-CMAC-96":
		return ClassAcceptable
	default: // SHA-256+, GMAC
		return ClassRecommended
	}
}

// SeverityForClass maps a policy class to a finding severity.
func SeverityForClass(class AlgorithmClass) Severity {
	switch class {
	case ClassProhibited:
		return SevHigh
	case ClassLegacy:
		return SevMedium
	default:
		return SevInfo
	}
}

// FixTemplate returns a strongSwan swanctl.conf proposal suggestion.
func FixTemplate(controlID string) string {
	switch controlID {
	case "C02":
		return "proposals = aes256gcm16-prfsha384-ecp384"
	case "C03":
		return "proposals = aes256gcm16-prfsha384-ecp384"
	case "C04":
		return "proposals = aes256gcm16-prfsha384-ecp384"
	case "C05":
		return "proposals = aes256gcm16-prfsha384-ecp384  # remove weak proposals"
	case "C07":
		return "auth = pubkey  # use certificate authentication"
	case "C10":
		return "rekey_time = 8h  # for IKE; use 1h for child SAs"
	case "C11":
		return "replay_window = 64"
	default:
		return ""
	}
}
