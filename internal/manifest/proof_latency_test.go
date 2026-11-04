//go:build integration && latency

// This is a measurement, not a check: it prints what /v1/decide costs with a
// proof and without one, on the built binary and a real Postgres, and asserts
// only that every answer was the one expected. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/wardryx_test?sslmode=disable \
//	    go test -tags 'integration latency' -run TestDecideLatency -v -timeout 30m ./internal/manifest/
package manifest

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// tokenFuseModelDeadline is the enforcement point's default wait for a decide on
// a model call, the budget this cost is read against.
const tokenFuseModelDeadline = 50 * time.Millisecond

type latencyCase struct {
	name      string
	db, proof bool
}

func envInt(name string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return fallback
}

func (in *instance) timedDecide(t testing.TB, client *http.Client, k liveKeys, token string) (time.Duration, int) {
	t.Helper()
	body := map[string]any{"agent_id": liveAgent, "run_id": "latency-run"}
	if token != "" {
		body["agent_token"] = token
		body["agent_dpop_proof"] = k.proof(t, token)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+in.addr+"/v1/decide", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+liveKey)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/decide: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return time.Since(start), resp.StatusCode
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	return sorted[int(float64(len(sorted)-1)*p)]
}

func TestDecideLatencyWithAndWithoutAProof(t *testing.T) {
	dsn := liveDSN(t)
	bin := buildServe(t)
	k := newLiveKeys(t)
	requests := envInt("LATENCY_REQUESTS", 4000)
	rounds := envInt("LATENCY_ROUNDS", 3)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	counters := func() (wal, sessions int64) {
		ctx := context.Background()
		if err := db.QueryRowContext(ctx, `SELECT (pg_current_wal_lsn() - '0/0')::bigint`).Scan(&wal); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT sessions FROM pg_stat_database WHERE datname = current_database()`).Scan(&sessions); err != nil {
			t.Fatal(err)
		}
		return wal, sessions
	}

	cases := []latencyCase{
		{"no token, memory store", false, false},
		{"no token, Postgres store", true, false},
		{"proof, record in the process", false, true},
		{"proof, shared record", true, true},
	}
	fmt.Printf("%-30s %5s %7s %9s %9s %9s %9s %6s %9s %9s\n", "case", "conc", "n", "p50", "p95", "p99", "max", ">50ms", "WAL B/req", "sessions")
	for _, conc := range []int{1, 8, 32} {
		for _, c := range cases {
			var all []time.Duration
			var walBytes, newSessions int64
			for round := 0; round < rounds; round++ {
				store := ""
				if c.db {
					store = dsn
				}
				in := startServe(t, bin, k, store)
				token := ""
				if c.proof {
					token = k.token(t)
				}
				client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: conc}}
				// A warm connection and a warm token cache, as a running service has.
				for i := 0; i < 50; i++ {
					if _, code := in.timedDecide(t, client, k, token); code != http.StatusOK {
						t.Fatalf("%s: warm-up answered %d", c.name, code)
					}
				}
				wal0, sess0 := counters()
				samples := make([][]time.Duration, conc)
				var wg sync.WaitGroup
				for w := 0; w < conc; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for i := 0; i < requests/conc; i++ {
							took, code := in.timedDecide(t, client, k, token)
							if code != http.StatusOK {
								t.Errorf("%s: answered %d", c.name, code)
								return
							}
							samples[w] = append(samples[w], took)
						}
					}()
				}
				wg.Wait()
				wal1, sess1 := counters()
				walBytes += wal1 - wal0
				newSessions += sess1 - sess0
				for _, s := range samples {
					all = append(all, s...)
				}
				in.stop()
				client.CloseIdleConnections()
			}
			sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
			over := sort.Search(len(all), func(i int) bool { return all[i] > tokenFuseModelDeadline })
			fmt.Printf("%-30s %5d %7d %9s %9s %9s %9s %6d %9d %9d\n", c.name, conc, len(all),
				percentile(all, 0.50).Round(time.Microsecond), percentile(all, 0.95).Round(time.Microsecond),
				percentile(all, 0.99).Round(time.Microsecond), all[len(all)-1].Round(time.Microsecond),
				len(all)-over, walBytes/int64(len(all)), newSessions)
		}
	}
}
