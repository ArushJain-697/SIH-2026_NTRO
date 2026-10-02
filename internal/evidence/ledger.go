// Package evidence provides the evidence ledger — a structured record of every
// fact TRACE extracts, with status, confidence, provenance, and resolution.
package evidence

import (
	"fmt"
	"sort"
)

// Status indicates how an evidence value was obtained.
type Status string

const (
	StatusObserved        Status = "OBSERVED"
	StatusDerived         Status = "DERIVED"
	StatusInferred        Status = "INFERRED"
	StatusGatewayVerified Status = "GATEWAY_VERIFIED"
	StatusConflicting     Status = "CONFLICTING"
	StatusUnknown         Status = "UNKNOWN"
)

// Precedence ordering for resolution.
var statusPrecedence = map[Status]int{
	StatusGatewayVerified: 5,
	StatusObserved:        4,
	StatusDerived:         3,
	StatusInferred:        2,
	StatusUnknown:         1,
	StatusConflicting:     6, // special: only when two sources disagree
}

// SourceKind identifies the origin of evidence.
type SourceKind string

const (
	SourcePacket   SourceKind = "packet"
	SourceDerived  SourceKind = "derived"
	SourceGateway  SourceKind = "gateway"
	SourceInferred SourceKind = "inferred"
)

// Source describes where evidence came from.
type Source struct {
	Kind      SourceKind `json:"kind"`
	Packets   []int      `json:"packets,omitempty"`
	Exchange  string     `json:"exchange,omitempty"`
	MessageID uint32     `json:"message_id,omitempty"`
	Detail    string     `json:"detail,omitempty"`
}

// Resource identifies the object an evidence item applies to.
type Resource struct {
	Type string `json:"type"` // "ike_sa", "child_sa", "analysis"
	ID   string `json:"id"`
}

// Value holds the structured evidence value.
type Value struct {
	Algorithm  string `json:"algorithm,omitempty"`
	KeyBits    int    `json:"key_bits,omitempty"`
	ICVBits    int    `json:"icv_bits,omitempty"`
	RegistryID string `json:"registry_id,omitempty"`
	Raw        string `json:"raw,omitempty"`
	Bool       *bool  `json:"bool,omitempty"`
	Uint       uint64 `json:"uint,omitempty"`
}

// Evidence is one fact in the ledger.
type Evidence struct {
	ID         string   `json:"id"`
	Property   string   `json:"property"`
	Value      Value    `json:"value"`
	Status     Status   `json:"status"`
	Confidence float64  `json:"confidence"`
	Resource   Resource `json:"resource"`
	Source     Source   `json:"source"`
}

// Ledger holds all evidence for one analysis.
type Ledger struct {
	items  []Evidence
	nextID int
}

// NewLedger creates an empty evidence ledger.
func NewLedger() *Ledger {
	return &Ledger{}
}

// Add appends evidence to the ledger and returns its assigned ID.
func (l *Ledger) Add(e Evidence) string {
	l.nextID++
	e.ID = fmt.Sprintf("E%04d", l.nextID)

	// Set default confidence based on status.
	if e.Confidence == 0 {
		switch e.Status {
		case StatusObserved:
			e.Confidence = 1.0
		case StatusGatewayVerified:
			e.Confidence = 1.0
		case StatusDerived:
			e.Confidence = 0.9
		case StatusInferred:
			e.Confidence = 0.7
		case StatusUnknown:
			e.Confidence = 0.0
		}
	}

	l.items = append(l.items, e)
	return e.ID
}

// All returns all evidence items.
func (l *Ledger) All() []Evidence {
	return l.items
}

// Count returns the number of evidence items.
func (l *Ledger) Count() int {
	return len(l.items)
}

// Resolve finds the highest-precedence evidence for a resource+property.
// If two eligible sources have different values, returns CONFLICTING.
func (l *Ledger) Resolve(resource Resource, property string) *Evidence {
	var candidates []Evidence
	for _, e := range l.items {
		if e.Resource.Type == resource.Type && e.Resource.ID == resource.ID && e.Property == property {
			candidates = append(candidates, e)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	if len(candidates) == 1 {
		return &candidates[0]
	}

	// Sort by precedence (highest first).
	sort.Slice(candidates, func(i, j int) bool {
		return statusPrecedence[candidates[i].Status] > statusPrecedence[candidates[j].Status]
	})

	// Check for conflicting values at the same precedence level.
	top := candidates[0]
	for _, c := range candidates[1:] {
		if statusPrecedence[c.Status] == statusPrecedence[top.Status] {
			if c.Value.Algorithm != top.Value.Algorithm || c.Value.KeyBits != top.Value.KeyBits {
				conflicting := top
				conflicting.Status = StatusConflicting
				conflicting.Confidence = 0.5
				return &conflicting
			}
		}
	}

	return &top
}

// ForResource returns all evidence for a resource.
func (l *Ledger) ForResource(resource Resource) []Evidence {
	var result []Evidence
	for _, e := range l.items {
		if e.Resource.Type == resource.Type && e.Resource.ID == resource.ID {
			result = append(result, e)
		}
	}
	return result
}
