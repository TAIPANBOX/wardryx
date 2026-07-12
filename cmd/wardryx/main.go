// Command wardryx is the policy and action-authorization plane (a Policy
// Decision Point) for the TAIPANBOX agent-governance stack.
//
// Wardryx is a defensive, self-protection component: it decides whether an
// operator's own agent may take an action, and blocks or holds it. It never
// performs an action itself and never attacks or acts against anyone else.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/api"
	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/passports"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// version is overridden at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wardryx:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("no command given")
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "check":
		return runCheck(args[1:])
	case "approvals":
		return runApprovals(args[1:])
	case "version":
		fmt.Println("wardryx", version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: wardryx <command> [flags]

commands:
  serve      run the HTTP policy decision API
  check      offline dry-run: evaluate a directory of agent passports against a policy
  approvals  list pending/decided approvals from Postgres (-db)
  version    print version

Every serve flag (-addr, -policy, -db, -events) falls back to its
WARDRYX_* environment variable when the flag itself is unset; WARDRYX_KEYS,
WARDRYX_APPROVAL_SECRET, and WARDRYX_APPROVAL_SINGLE_USE are
environment-only (no flag).`)
}

// --- serve ---

func runServe(args []string) error {
	cfg := config.FromEnv()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", orDefault(cfg.Addr, ":8090"), "address to listen on (WARDRYX_ADDR)")
	policyPath := fs.String("policy", cfg.Policy, "policy file or directory, YAML or JSON (WARDRYX_POLICY); empty allows every request")
	dbDSN := fs.String("db", cfg.DB, "Postgres DSN (WARDRYX_DB); empty uses an in-memory approval store")
	eventsPath := fs.String("events", cfg.EventsPath, "NDJSON path for agent-event output (WARDRYX_EVENTS_PATH); empty disables events")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wardryx serve [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	policies, err := policy.Load(*policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "wardryx: no -policy given; running with zero policies, every request will be allowed")
	} else {
		fmt.Fprintf(os.Stderr, "wardryx: loaded %d policy(ies) from %s, version %s\n", policies.Len(), *policyPath, policies.Version())
	}
	if cfg.ApprovalSecret == "" && policies.RequiresHumanApproval() {
		fmt.Fprintln(os.Stderr, "wardryx: WARDRYX_APPROVAL_SECRET is empty but a policy requires human approval; hold decisions cannot be granted until it is set")
	}

	var st store.Store
	if *dbDSN != "" {
		pg, err := store.OpenPostgres(context.Background(), *dbDSN)
		if err != nil {
			return fmt.Errorf("open postgres: %w", err)
		}
		defer pg.Close()
		st = pg
	} else {
		fmt.Fprintln(os.Stderr, "wardryx: no -db given; using an in-memory approval store (state is lost on restart)")
		st = store.NewMemory()
	}
	if warn := singleUseInMemoryWarning(cfg.ApprovalSingleUse, *dbDSN); warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}

	var events *event.Writer
	if *eventsPath != "" {
		ew, err := event.NewWriter(*eventsPath)
		if err != nil {
			return fmt.Errorf("open events writer: %w", err)
		}
		defer ew.Close()
		events = ew
	}

	keys := api.ParseKeys(cfg.Keys)
	engine := pdp.New(policies, []byte(cfg.ApprovalSecret))
	srv := api.New(engine, st, events, keys, []byte(cfg.ApprovalSecret), cfg.ApprovalSingleUse)

	fmt.Fprintf(os.Stderr, "wardryx: serving on http://%s\n", displayAddr(*addr))
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

// singleUseInMemoryWarning returns the stderr warning to print when
// WARDRYX_APPROVAL_SINGLE_USE is enabled but serve is about to use the
// in-memory approval store (dbDSN empty): Memory.TryRedeem's claimed keys
// live only in this one process, so single-use only holds within it, not
// across multiple wardryx instances sharing the load (e.g. behind a load
// balancer) -- durable, cross-instance single-use needs -db/WARDRYX_DB.
// Returns "" (no warning) when singleUse is false or dbDSN is set.
func singleUseInMemoryWarning(singleUse bool, dbDSN string) string {
	if !singleUse || dbDSN != "" {
		return ""
	}
	return "wardryx: WARDRYX_APPROVAL_SINGLE_USE=true with no -db (in-memory approval store); single-use is only enforced within this one process, not across multiple wardryx instances -- pass -db for single-use that holds across a multi-instance deployment"
}

func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// --- check ---

// checkResult is one passport's offline dry-run outcome.
type checkResult struct {
	AgentID  string
	Owner    string
	Decision string
	Reason   string
}

// checkAgents loads every passport under passportDir and the policy set at
// policyPath, and evaluates each passport's current attestation posture
// against it via the same pdp.Engine.Decide used by the live API. A
// Passport carries no tool list, cost estimate, step count, or domain list
// (it is static identity metadata, not an in-flight action), so ToolNames,
// EstCostUSD, Steps, and Domains are left at their zero values: only
// deny_if_unattested (and, trivially, whether any policy targets the agent
// at all) is meaningfully exercised by a dry-run over passports alone.
// deny_tool/require_human_above_usd/deny_above_usd/max_steps/allow_domains
// rules only ever fire against a real, in-flight DecideRequest from
// /v1/decide.
func checkAgents(passportDir, policyPath string) ([]checkResult, passports.Report, string, error) {
	ids, rep, err := passports.Load(passportDir)
	if err != nil {
		return nil, passports.Report{}, "", fmt.Errorf("load passports: %w", err)
	}
	policies, err := policy.Load(policyPath)
	if err != nil {
		return nil, passports.Report{}, "", fmt.Errorf("load policy: %w", err)
	}
	engine := pdp.New(policies, nil)

	results := make([]checkResult, 0, len(ids))
	for _, p := range ids {
		method := ""
		if p.Attestation != nil {
			method = p.Attestation.Method
		}
		resp := engine.Decide(pdp.DecideRequest{
			AgentID:           p.ID,
			RunID:             "offline-check",
			AttestationMethod: method,
		})
		results = append(results, checkResult{
			AgentID:  p.ID,
			Owner:    p.Owner,
			Decision: resp.Decision,
			Reason:   resp.Reason,
		})
	}
	return results, rep, policies.Version(), nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	format := fs.String("format", "human", "output format: human|json")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wardryx check [flags] <passport-dir> <policy>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("check requires exactly two arguments: <passport-dir> <policy>")
	}

	results, rep, version, err := checkAgents(fs.Arg(0), fs.Arg(1))
	if err != nil {
		return err
	}
	if rep.Malformed > 0 {
		fmt.Fprintf(os.Stderr, "wardryx: passports %s: %d file(s) read, %d malformed\n", fs.Arg(0), rep.Files, rep.Malformed)
	}

	switch *format {
	case "human":
		printCheckHuman(os.Stdout, results, version)
	case "json":
		if err := printCheckJSON(os.Stdout, results); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return nil
}

func printCheckHuman(w io.Writer, results []checkResult, policyVersion string) {
	fmt.Fprintf(w, "wardryx: %d passport(s) checked against policy version %s\n\n", len(results), policyVersion)
	if len(results) == 0 {
		fmt.Fprintln(w, "No passports found.")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tOWNER\tDECISION\tREASON")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.AgentID, r.Owner, r.Decision, r.Reason)
	}
	_ = tw.Flush()
}

type checkResultJSON struct {
	AgentID  string `json:"agent_id"`
	Owner    string `json:"owner"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func printCheckJSON(w io.Writer, results []checkResult) error {
	out := make([]checkResultJSON, 0, len(results))
	for _, r := range results {
		// checkResult and checkResultJSON share the same field
		// names/types/order (only the JSON tags differ), so a direct
		// conversion is equivalent to copying field by field.
		out = append(out, checkResultJSON(r))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- approvals ---

func runApprovals(args []string) error {
	cfg := config.FromEnv()
	fs := flag.NewFlagSet("approvals", flag.ContinueOnError)
	dbDSN := fs.String("db", cfg.DB, "Postgres DSN (required; WARDRYX_DB)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wardryx approvals -db <dsn>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dbDSN == "" {
		fs.Usage()
		return fmt.Errorf("approvals requires -db (or WARDRYX_DB): a freshly started in-memory store would always be empty")
	}

	ctx := context.Background()
	pg, err := store.OpenPostgres(ctx, *dbDSN)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer pg.Close()

	list, err := pg.ListApprovals(ctx)
	if err != nil {
		return fmt.Errorf("list approvals: %w", err)
	}
	if len(list) == 0 {
		fmt.Println("No approvals recorded.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "APPROVAL_ID\tAGENT\tRUN\tSTATUS\tDECIDED_BY\tREQUESTED_AT")
	for _, a := range list {
		status := "pending"
		if !a.Pending() {
			status = a.Decision
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			a.ApprovalID, a.AgentID, a.RunID, status, orDash(a.DecidedBy), a.RequestedAt.UTC().Format("2006-01-02 15:04:05Z"))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
