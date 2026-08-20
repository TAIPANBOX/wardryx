package approval

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The two readers of a held approval's Context. Both were around 72%, and the
// uncovered branches are the ones that decide what happens when the shape is
// not what was expected.
//
// costFromContext is the sharper of the two. The cost it returns is the
// CEILING the grant's approval token is minted against: an action was held
// because it would spend more than the policy allows, a human granted it, and
// this number is what bounds what the grant actually permits. Falling back to
// zero for a shape it does not recognise is the safe direction, and it is
// worth a test precisely because the unsafe direction (guessing high, or
// panicking on a string) would be invisible.

func TestTheCostThatBoundsAGrantIsReadFromEveryShapeItArrivesIn(t *testing.T) {
	// The real shape. Anything that has been through the store has been
	// through JSON, and a JSON number in a map[string]any is a float64.
	roundTripped := map[string]any{}
	raw, _ := json.Marshal(map[string]any{"est_cost_usd": 1250.75})
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatal(err)
	}
	if got := costFromContext(roundTripped); got != 1250.75 {
		t.Fatalf("a cost that round-tripped through JSON read as %v, want 1250.75. "+
			"This is the ceiling the grant's token is minted against", got)
	}

	// An int, which only a hand-built Approval produces, is tolerated rather
	// than dropped to zero: dropping it would mint a grant bounded at nothing.
	if got := costFromContext(map[string]any{"est_cost_usd": 500}); got != 500 {
		t.Fatalf("an int cost read as %v, want 500", got)
	}
}

func TestAnUnreadableCostFallsBackToZeroRatherThanGuessing(t *testing.T) {
	cases := []struct {
		name string
		ctx  map[string]any
	}{
		{"no entry at all", map[string]any{}},
		{"a nil context", nil},
		{"a string where a number belongs", map[string]any{"est_cost_usd": "1250.75"}},
		{"an explicit null", map[string]any{"est_cost_usd": nil}},
		{"a list", map[string]any{"est_cost_usd": []any{1, 2}}},
		{"a nested object", map[string]any{"est_cost_usd": map[string]any{"amount": 1}}},
		{"a bool", map[string]any{"est_cost_usd": true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := costFromContext(c.ctx)
			if got != 0 {
				t.Fatalf("costFromContext returned %v. Zero is the safe "+
					"direction here: a ceiling read out of a shape nothing "+
					"understands is a grant bounded by a guess", got)
			}
		})
	}
}

func TestTheToolListIsReadFromBothShapesItArrivesIn(t *testing.T) {
	// What every real Context looks like once it has been through JSON.
	afterJSON := map[string]any{"tool_names": []any{"send_wire_transfer", "read_file"}}
	want := []string{"send_wire_transfer", "read_file"}
	if got := toolsFromContext(afterJSON); !reflect.DeepEqual(got, want) {
		t.Fatalf("toolsFromContext(%v) = %v, want %v", afterJSON, got, want)
	}

	// And the hand-built shape, which only a test produces.
	direct := map[string]any{"tool_names": []string{"send_wire_transfer"}}
	if got := toolsFromContext(direct); !reflect.DeepEqual(got, []string{"send_wire_transfer"}) {
		t.Fatalf("toolsFromContext(%v) = %v", direct, got)
	}
}

// A list with a non-string in it keeps the strings and drops the rest, rather
// than returning nothing. Returning nothing would silently widen the grant:
// the tool that caused the hold would no longer be named on it.
func TestANonStringInTheToolListDoesNotTakeTheOthersWithIt(t *testing.T) {
	ctx := map[string]any{"tool_names": []any{"send_wire_transfer", 42, nil, "read_file"}}
	want := []string{"send_wire_transfer", "read_file"}
	got := toolsFromContext(ctx)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("toolsFromContext = %v, want %v. Dropping the whole list "+
			"because one entry was not a string would leave the grant naming "+
			"no tool at all", got, want)
	}
}

func TestAnUnreadableToolListIsNilRatherThanEmpty(t *testing.T) {
	cases := []struct {
		name string
		ctx  map[string]any
	}{
		{"no entry", map[string]any{}},
		{"a nil context", nil},
		{"a string instead of a list", map[string]any{"tool_names": "send_wire_transfer"}},
		{"an explicit null", map[string]any{"tool_names": nil}},
		{"an object", map[string]any{"tool_names": map[string]any{"0": "x"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := toolsFromContext(c.ctx); got != nil {
				t.Fatalf("toolsFromContext returned %v, want nil", got)
			}
		})
	}
}

// An empty list is a list, and it is not the same fact as no list at all. One
// says the hold named no tools; the other says nobody recorded any.
func TestAnEmptyToolListIsNotTheSameAsNoToolList(t *testing.T) {
	empty := toolsFromContext(map[string]any{"tool_names": []any{}})
	absent := toolsFromContext(map[string]any{})
	if empty == nil {
		t.Fatal("an explicitly empty tool list read as absent. The hold named " +
			"no tools, which is a different fact from nobody having recorded any")
	}
	if len(empty) != 0 {
		t.Fatalf("an empty list read as %v", empty)
	}
	if absent != nil {
		t.Fatalf("an absent tool list read as %v", absent)
	}
}
