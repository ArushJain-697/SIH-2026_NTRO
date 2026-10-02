package engine

import (
	"bytes"
	"testing"

	"github.com/SIH-2026/trace/internal/testutil"
)

func TestAnalyzeIKEv2GCM(t *testing.T) {
	data := testutil.BuildIKEv2GCMCapture()
	result, err := Analyze(bytes.NewReader(data), int64(len(data)), Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.State != StateCompleted {
		t.Errorf("state = %s, want COMPLETED", result.State)
	}

	if len(result.IKESAs) == 0 {
		t.Fatal("expected IKE SAs")
	}

	if result.Assessment == nil {
		t.Fatal("expected assessment")
	}

	// C02 should not be UNKNOWN for an IKEv2 capture with visible crypto.
	for _, c := range result.Assessment.Controls {
		if c.ID == "C02" && c.Status == "UNKNOWN" {
			t.Errorf("C02 IKE Encryption is UNKNOWN — this is the W1 bug")
		}
		if c.ID == "C04" && c.Status == "UNKNOWN" {
			t.Errorf("C04 DH Group is UNKNOWN")
		}
	}

	// Coverage should be > 0.
	if result.Assessment.Headline.Coverage == 0 {
		t.Error("coverage = 0, expected > 0")
	}

	// Should have child SAs.
	if result.ChildSAs == 0 {
		t.Error("expected child SA pairs")
	}

	// Evidence should be non-empty.
	if len(result.Evidence) == 0 {
		t.Error("expected evidence entries")
	}

	t.Logf("Score=%.1f Coverage=%.1f%% Risk=%s Label=%s",
		result.Assessment.Headline.Score,
		result.Assessment.Headline.Coverage,
		result.Assessment.Headline.RiskLevel,
		result.Assessment.Headline.Label)
}

func TestAnalyzeIKEv2CBC(t *testing.T) {
	data := testutil.BuildIKEv2CBCCapture()
	result, err := Analyze(bytes.NewReader(data), int64(len(data)), Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.State != StateCompleted {
		t.Errorf("state = %s, want COMPLETED", result.State)
	}

	// C02 should evaluate the CBC cipher.
	for _, c := range result.Assessment.Controls {
		if c.ID == "C02" && c.Status == "UNKNOWN" {
			t.Error("C02 should not be UNKNOWN for AES-CBC")
		}
	}
}

func TestAnalyzeNonIPsec(t *testing.T) {
	data := testutil.BuildNonIPsecCapture()
	result, err := Analyze(bytes.NewReader(data), int64(len(data)), Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.State != StateCompletedNoIPs {
		t.Errorf("state = %s, want COMPLETED_NO_IPSEC", result.State)
	}

	// Should NOT be an empty success (fixes W6).
	if result.Input.Stats.Seen == 0 {
		t.Error("seen packets should not be 0")
	}
}

func TestAnalyzeStrictProfile(t *testing.T) {
	data := testutil.BuildIKEv2CBCCapture()
	result, err := Analyze(bytes.NewReader(data), int64(len(data)), Options{Profile: "strict"})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.Assessment.Profile != "strict" {
		t.Errorf("profile = %s, want strict", result.Assessment.Profile)
	}
}
