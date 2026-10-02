package iana

import "testing"

func TestLookupKnown(t *testing.T) {
	tr, ok := Lookup(TypeEncryption, 20, 256)
	if !ok {
		t.Fatal("expected AES-GCM-16-256 to be found")
	}
	if tr.Name != "AES-GCM-16-256" {
		t.Errorf("name = %s, want AES-GCM-16-256", tr.Name)
	}
	if !tr.AEAD {
		t.Error("expected AEAD = true")
	}
	if tr.ICVBits != 128 {
		t.Errorf("ICVBits = %d, want 128", tr.ICVBits)
	}
}

func TestLookupUnknown(t *testing.T) {
	tr, ok := Lookup(TypeEncryption, 999, 0)
	if ok {
		t.Error("expected unknown to return false")
	}
	if tr.Family != FamilyOther {
		t.Errorf("family = %s, want Other", tr.Family)
	}
	expected := "UNKNOWN(ENCR,999)"
	if tr.Name != expected {
		t.Errorf("name = %s, want %s", tr.Name, expected)
	}
}

func TestLookupDH(t *testing.T) {
	tr, ok := LookupDH(19)
	if !ok {
		t.Fatal("expected ECP-256 to be found")
	}
	if tr.Name != "ECP-256" {
		t.Errorf("name = %s, want ECP-256", tr.Name)
	}
	if tr.KeyBits != 256 {
		t.Errorf("keyBits = %d, want 256", tr.KeyBits)
	}
}

func TestAllRoundTrip(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() returned empty")
	}

	for _, tr := range all {
		got, ok := Lookup(tr.Type, tr.ID, tr.KeyBits)
		if !ok {
			t.Errorf("Lookup(%s, %d, %d) = not found", tr.Type, tr.ID, tr.KeyBits)
			continue
		}
		if got.Name != tr.Name {
			t.Errorf("round-trip mismatch: %s != %s", got.Name, tr.Name)
		}
	}
}

func TestIsValidExchange(t *testing.T) {
	cases := []struct {
		version uint8
		exch    ExchangeType
		valid   bool
	}{
		{2, ExchIKE_SA_INIT, true},
		{2, ExchIKE_AUTH, true},
		{2, ExchIKE_INTERMEDIATE, true},
		{2, ExchIKE_FOLLOWUP_KE, true},
		{2, ExchV1Main, false},
		{1, ExchV1Main, true},
		{1, ExchV1Aggressive, true},
		{1, ExchIKE_SA_INIT, false},
	}

	for _, tc := range cases {
		got := IsValidExchange(tc.version, tc.exch)
		if got != tc.valid {
			t.Errorf("IsValidExchange(%d, %s) = %v, want %v", tc.version, tc.exch, got, tc.valid)
		}
	}
}
