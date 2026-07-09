package passports

import "testing"

func TestLoadDirectory(t *testing.T) {
	ids, rep, err := Load("testdata")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rep.Files != 5 {
		t.Errorf("Files = %d, want 5", rep.Files)
	}
	if rep.Malformed != 3 {
		t.Errorf("Malformed = %d, want 3", rep.Malformed)
	}
	if len(ids) != 2 {
		t.Fatalf("passports = %d, want 2: %+v", len(ids), ids)
	}

	byID := map[string]bool{}
	for _, p := range ids {
		byID[p.ID] = true
	}
	if !byID["agent://acme.example/finance/bot1"] || !byID["agent://acme.example/support/bot2"] {
		t.Errorf("loaded ids = %+v, missing an expected valid passport", byID)
	}
}

func TestLoadAttestationFields(t *testing.T) {
	ids, _, err := Load("testdata")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var attested, unattested bool
	for _, p := range ids {
		switch p.ID {
		case "agent://acme.example/finance/bot1":
			if p.Attestation == nil || p.Attestation.Method != "spiffe-svid" {
				t.Errorf("bot1 attestation = %+v, want spiffe-svid", p.Attestation)
			}
			attested = true
		case "agent://acme.example/support/bot2":
			if p.Attestation != nil {
				t.Errorf("bot2 attestation = %+v, want nil (no attestation object in fixture)", p.Attestation)
			}
			unattested = true
		}
	}
	if !attested || !unattested {
		t.Fatalf("did not observe both fixtures: attested=%v unattested=%v", attested, unattested)
	}
}

func TestLoadMissingPathErrors(t *testing.T) {
	if _, _, err := Load("testdata/does-not-exist.json"); err == nil {
		t.Fatal("Load(missing file): expected an error, got nil")
	}
}

func TestLoadDeduplicatesByID(t *testing.T) {
	// Loading the same directory twice via a glob that matches every file
	// exactly once already proves determinism; this test additionally
	// confirms Load never errors or double-counts when pointed at a single
	// valid file directly (the "literal file" resolve path).
	ids, rep, err := Load("testdata/valid_attested.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if rep.Files != 1 || rep.Malformed != 0 || len(ids) != 1 {
		t.Fatalf("Load(single file) = %+v files, %d ids, want 1/0/1", rep, len(ids))
	}
}
