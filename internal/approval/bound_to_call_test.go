package approval

import (
	"errors"
	"testing"
)

// VerifyApprovalTokenBoundToCall is the verifier for a hold that only an
// approval of the call itself may lift. It refuses everything the ordinary
// verifier refuses, and a token that binds no call besides.
func TestATokenThatBindsNoCallIsRefusedWhereTheCallMustBeBound(t *testing.T) {
	call := digestOf(`{"bucket":"prod-backups"}`)
	strict := func(tok, digest string) error {
		return VerifyApprovalTokenBoundToCall(bindSecret, tok, bindAgent, bindRun, bindTools, 100, digest)
	}

	if err := strict(boundToken(t, call), call); err != nil {
		t.Fatalf("the token bound to this call was refused: %v", err)
	}

	unbound, _, err := MintApprovalToken(bindSecret, bindAgent, bindRun, bindTools, 100, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	// The ordinary verifier accepts it (invariant 28's named limit); this one
	// does not, on a request with a call or without one.
	if err := verifyFor(unbound, call); err != nil {
		t.Fatalf("control: the unbound token no longer verifies at all: %v", err)
	}
	for name, digest := range map[string]string{"with a call": call, "with no call": ""} {
		if err := strict(unbound, digest); !errors.Is(err, ErrTokenUnbound) {
			t.Errorf("an unbound token %s: %v, want ErrTokenUnbound", name, err)
		}
	}

	// What the ordinary verifier refuses comes back unchanged.
	if err := strict(boundToken(t, call), digestOf(`{"bucket":"other"}`)); !errors.Is(err, ErrTokenToolCall) {
		t.Errorf("a token for another call: %v, want ErrTokenToolCall", err)
	}
	if err := strict("garbage", call); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("garbage: %v, want ErrTokenMalformed", err)
	}
	if err := VerifyApprovalTokenBoundToCall(nil, boundToken(t, call), bindAgent, bindRun, bindTools, 100, call); !errors.Is(err, ErrNoSecret) {
		t.Errorf("no secret: %v, want ErrNoSecret", err)
	}
}
