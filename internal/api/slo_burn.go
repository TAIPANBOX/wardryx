package api

import (
	"fmt"
	"log"
	"strings"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/sloburn"
)

// WithSLOBurn attaches the reader of the quality plane's event file
// (WARDRYX_SIGNAL_EVENTS; invariant 45). Nil, the default, reads nothing: a
// request's signals are what the caller sent, and a decision is made as it was.
//
// With a reader, every decide request gains one standing signal named slo_burn
// for the agent it is about, and carries room for fifteen signals of its own.
// The decision engine does not know the signal came from a file: it reads it as
// it reads any signal, so a hold_if_signal rule on slo_burn can add a hold and
// nothing else, and without such a rule nothing changes.
func (s *Server) WithSLOBurn(r *sloburn.Reader) *Server {
	s.sloBurn = r
	return s
}

// withStandingSignal returns the signals a decide request is decided with: the
// caller's, less any named slo_burn, plus the standing signal for the agent when
// the file can be believed. It is the only place the signal enters a decision.
//
// A caller's own slo_burn signal is dropped, not refused. The name is compared
// the way a rule compares it (case and surrounding space folded), so no
// spelling of it gets past. Keeping it would let a caller lift a hold by
// declaring the agent fine, and, while the file cannot be read, let it stand in
// for the signal that is missing: a hold_if_signal rule with when_absent: hold
// holds only a request with no signal of its name at all.
//
// The standing signal is added after the caller's signals have been validated,
// and the caller is given room for it: replay validates the signals a record
// carries by the same cap, so a record of sixteen would not replay. The second
// return is the sentence of a 400 when the caller sent too many.
//
// When the file cannot be believed there is no standing signal. What that means
// is the policy's to say, through when_absent; it is never turned into an
// answer here.
func (s *Server) withStandingSignal(caller []pdp.Signal, agentID string) ([]pdp.Signal, string) {
	if s.sloBurn == nil {
		return caller, ""
	}
	kept := make([]pdp.Signal, 0, len(caller)+1)
	dropped := 0
	for _, sg := range caller {
		if strings.EqualFold(strings.TrimSpace(sg.Name), sloburn.SignalName) {
			dropped++
			continue
		}
		kept = append(kept, sg)
	}
	if dropped > 0 {
		s.sloBurnDroppedOnce.Do(func() {
			log.Printf("wardryx: a decide request carries a signal named %s, which wardryx supplies itself while WARDRYX_SIGNAL_EVENTS is set; it is dropped (logged once per process)", sloburn.SignalName)
		})
	}
	if len(kept) > pdp.MaxSignals-1 {
		return nil, fmt.Sprintf("at most %d signals per request while WARDRYX_SIGNAL_EVENTS is set, got %d", pdp.MaxSignals-1, len(kept))
	}
	if sg, ok := s.sloBurn.For(agentID); ok {
		kept = append(kept, pdp.Signal{Name: sg.Name, Value: sg.Value, Probability: sg.Probability, Source: sg.Source, AnswerID: sg.AnswerID})
	}
	return kept, ""
}
