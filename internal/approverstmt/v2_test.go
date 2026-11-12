package approverstmt

import (
	"strings"
	"testing"
	"time"
)

// claimsV2At is a valid version 2 statement's claims: the call and the
// preview the person was shown.
func claimsV2At(now time.Time, tcd, pvd string) map[string]any {
	c := claimsAt(now)
	c["v"] = 2
	c["tcd"] = tcd
	c["pvd"] = pvd
	return c
}

func TestAVersion2StatementNamesTheCallAndThePreviewThePersonWasShown(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	tcd, pvd := strings.Repeat("a", 64), strings.Repeat("b", 64)
	got, err := verifierFor(t, k).Verify(sign(t, k, headerFor(t, k), claimsV2At(now, tcd, pvd)), aid, dec, now)
	if err != nil {
		t.Fatalf("a version 2 statement was refused: %v", err)
	}
	if got.Version != 2 || got.ToolCallDigest != tcd || got.PreviewDigest != pvd {
		t.Fatalf("verified %+v", got)
	}
	// none is how a statement says no preview was shown, and no call named.
	got, err = verifierFor(t, k).Verify(sign(t, k, headerFor(t, k), claimsV2At(now, None, None)), aid, dec, now)
	if err != nil || got.PreviewDigest != None || got.ToolCallDigest != None {
		t.Fatalf("a blind version 2 statement: %+v %v", got, err)
	}
}

func TestAVersion2StatementWithAMalformedDigestIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	good := strings.Repeat("a", 64)
	for _, bad := range []any{"", "None", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("z", 64), 7, nil} {
		for _, field := range []string{"tcd", "pvd"} {
			c := claimsV2At(now, good, good)
			if bad == nil {
				delete(c, field)
			} else {
				c[field] = bad
			}
			if _, err := verifierFor(t, k).Verify(sign(t, k, headerFor(t, k), c), aid, dec, now); !refused(err) {
				t.Errorf("%s = %v accepted: %v", field, bad, err)
			}
		}
	}
}

func TestAVersion1StatementCannotCarryTheVersion2ClaimsAndOtherVersionsAreRefused(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	for _, field := range []string{"tcd", "pvd"} {
		c := claimsAt(now)
		c[field] = strings.Repeat("a", 64)
		if _, err := verifierFor(t, k).Verify(sign(t, k, headerFor(t, k), c), aid, dec, now); !refused(err) {
			t.Errorf("a version 1 statement with %s was accepted: %v", field, err)
		}
	}
	for _, v := range []any{0, 3, 2.5, "2"} {
		c := claimsV2At(now, None, None)
		c["v"] = v
		if _, err := verifierFor(t, k).Verify(sign(t, k, headerFor(t, k), c), aid, dec, now); !refused(err) {
			t.Errorf("v = %v accepted: %v", v, err)
		}
	}
}
