// The declaration in components.json is only worth reading if this repository
// proves it, and proves it by RUNNING rather than by describing.
//
// estate-gates cannot do this. It has no Go toolchain, and building twenty-two
// repositories in its CI is a matrix it does not have. This repository already
// runs its suite on every push, so the marginal cost of a process start is
// seconds.
//
// What is proved here is exactly the `checked` bucket and nothing else. The
// `declared` bucket is not asserted against anything, on purpose: a test that
// pretended to verify a sentence about purpose would be the failure this whole
// design exists to avoid.
package manifest

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// os/exec copies a process's output on its own goroutine, so reading what it
// has written while the process is still running is a data race and `-race`
// says so. These tests deliberately never wait for the process, because the
// claim under test is that it does NOT exit, so the buffer has to be the safe
// thing rather than the timing.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type envVar struct {
	Required bool   `json:"required"`
	Default  string `json:"default"`
}

type component struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Checked struct {
		Package                    string            `json:"package"`
		ListenDefault              string            `json:"listen_default"`
		HealthPath                 string            `json:"health_path"`
		Env                        map[string]envVar `json:"env"`
		StartsWithEmptyEnvironment bool              `json:"starts_with_empty_environment"`
		RefusesUnauthenticatedV1   bool              `json:"refuses_unauthenticated_v1"`
	} `json:"checked"`
}

type manifest struct {
	Schema     string      `json:"schema"`
	Repo       string      `json:"repo"`
	Components []component `json:"components"`
}

func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func load(t *testing.T) (manifest, string) {
	t.Helper()
	r := root(t)
	b, err := os.ReadFile(filepath.Join(r, "components.json"))
	if err != nil {
		t.Fatalf("reading components.json: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing components.json: %v", err)
	}
	if len(m.Components) == 0 {
		t.Fatal("components.json declares no component, so every test here measured nothing")
	}
	return m, r
}

func service(t *testing.T, m manifest) component {
	t.Helper()
	for _, c := range m.Components {
		if c.Class == "service" {
			return c
		}
	}
	t.Fatal("components.json declares no service, so the running half measured nothing")
	return component{}
}

// THE ONE THAT CLOSES THE HOLE. A binary this repository builds and does not
// declare is invisible from outside by construction, which is what estate-gates
// invariant 18 says about its own `runs` field.
func TestEveryBinaryThisRepositoryBuildsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	list := exec.Command("go", "list", "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./...")
	// Without this the command runs in THIS package's directory and `./...`
	// means this package alone. It then finds no main package, and the test
	// passes while measuring nothing.
	list.Dir = r
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	built := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			built[line] = true
		}
	}
	if len(built) == 0 {
		t.Fatal("go list found no main package in this repository, so this measured nothing")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		if c.Checked.Package == "" {
			t.Errorf("component %q declares no package", c.Name)
			continue
		}
		declared[c.Checked.Package] = true
	}
	for p := range built {
		if !declared[p] {
			t.Errorf("this repository builds %s and components.json does not declare it.\n"+
				"A component nobody declares is one no deployment can be asked to install.", p)
		}
	}
	for p := range declared {
		if !built[p] {
			t.Errorf("components.json declares %s and this repository does not build it", p)
		}
	}
}

// Every WARDRYX_ name in non-test source, against every one declared.
//
// It reads STRING LITERALS rather than walking calls to os.Getenv: config.go
// reads these through its own accessor, so a reader that followed os.Getenv
// call sites would report a set that is quietly short.
//
// A name ending in `_` is a PREFIX FRAGMENT and not a variable. `WARDRYX_*`
// appears in four doc comments and `WARDRYX_APPROVAL_` in one, and a check that
// demanded a manifest entry for those would be demanding a lie.
func TestEveryEnvironmentVariableThisRepositoryReadsIsDeclaredAndTheReverse(t *testing.T) {
	m, r := load(t)

	name := regexp.MustCompile(`WARDRYX_[A-Z0-9_]+`)
	inSource := map[string]bool{}
	fragments := 0
	err := filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range name.FindAllString(string(b), -1) {
			if strings.HasSuffix(n, "_") {
				fragments++
				continue
			}
			inSource[n] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(inSource) == 0 {
		t.Fatal("no WARDRYX_ name found in any non-test .go file, so this measured nothing")
	}
	if fragments == 0 {
		t.Log("no prefix fragment found; the filter above is now unexercised, which is " +
			"worth knowing before somebody deletes it as dead")
	}

	declared := map[string]bool{}
	for _, c := range m.Components {
		for k := range c.Checked.Env {
			declared[k] = true
		}
	}
	var missing, extra []string
	for n := range inSource {
		if !declared[n] {
			missing = append(missing, n)
		}
	}
	for n := range declared {
		if !inSource[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, n := range missing {
		t.Errorf("the code reads %s and components.json does not declare it", n)
	}
	for _, n := range extra {
		t.Errorf("components.json declares %s and no non-test source reads it", n)
	}
}

// The declared listen default is the one `serve` actually falls back to.
func TestTheDeclaredListenDefaultIsTheOneServeFallsBackTo(t *testing.T) {
	m, r := load(t)

	b, err := os.ReadFile(filepath.Join(r, "cmd", "wardryx", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	found := regexp.MustCompile(`orDefault\(cfg\.Addr,\s*"([^"]*)"\)`).FindStringSubmatch(string(b))
	if found == nil {
		t.Fatal("main.go no longer falls back for -addr through orDefault(cfg.Addr, ...), " +
			"so this measured nothing")
	}
	if got := service(t, m).Checked.ListenDefault; got != found[1] {
		t.Errorf("components.json says the default listen address is %q; main.go says %q",
			got, found[1])
	}
}

// AND THE HALF NO CENTRAL FILE COULD EVER DO: start it, twice over.
//
// It has no required variable: all nine carry a default or are optional. So the
// first claim is that it comes up with NOTHING configured, and answers its
// declared health path with no credential.
//
// The second claim is the one that exists because the opposite was written
// down. vouchryx's manifest test says in a comment that wardryx "installs a
// built-in admin key". ParseKeys("") returns an empty map, so with no
// WARDRYX_KEYS there is no key of any kind and every /v1 route answers 401.
// Fail-closed, and the only way to settle a sentence like that is to run it.
func TestItStartsUnconfiguredAndRefusesUnauthenticatedCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	m, r := load(t)
	svc := service(t, m)

	for k, v := range svc.Checked.Env {
		if v.Required {
			t.Fatalf("components.json marks %s required AND claims the service starts "+
				"with nothing configured. Those cannot both be true.", k)
		}
	}
	if !svc.Checked.StartsWithEmptyEnvironment {
		t.Skip("the manifest does not claim it starts unconfigured")
	}

	bin := filepath.Join(t.TempDir(), "wardryx")
	build := exec.Command("go", "build", "-o", bin, svc.Checked.Package)
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the declared package: %v\n%s", err, out)
	}

	// A port the OS picks, so a developer already running wardryx on the
	// declared default does not make this fail for a reason that is not a
	// finding. The DEFAULT itself is checked against main.go above, where it
	// can be checked without binding anything.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("releasing the reserved port: %v", err)
	}

	cmd := exec.Command(bin, "serve", "-addr", addr)
	// env -i, in Go. Nothing configured means nothing configured.
	cmd.Env = []string{}
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting it: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	health := "http://" + addr + svc.Checked.HealthPath
	var lastErr error
	up := false
	for i := 0; i < 50; i++ {
		resp, err := client.Get(health)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
				break
			}
			lastErr = nil
			t.Errorf("%s answered %d with no credential; the manifest declares it as the health path",
				svc.Checked.HealthPath, resp.StatusCode)
			break
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if !up && lastErr != nil {
		t.Fatalf("it never answered %s with an empty environment: %v\nits output was:\n%s",
			svc.Checked.HealthPath, lastErr, out.String())
	}

	if !svc.Checked.RefusesUnauthenticatedV1 {
		return
	}
	// One read and one decision, because they are authorised differently: every
	// /v1 route needs a bearer key and the policy routes additionally need the
	// admin role. Both must refuse, and refuse with 401 rather than by being
	// absent, which a 404 would also produce.
	for _, probe := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/policies"},
		{http.MethodPost, "/v1/decide"},
	} {
		req, err := http.NewRequest(probe.method, "http://"+addr+probe.path,
			strings.NewReader(`{"agent_id":"agent://x.example/a/b","action":"deploy","resource":"prod"}`))
		if err != nil {
			t.Fatalf("building the %s request: %v", probe.path, err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", probe.method, probe.path, err)
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d with no credential and no WARDRYX_KEYS set.\n"+
				"components.json claims this service is fail-closed, and 401 is the only "+
				"answer that makes that true.", probe.method, probe.path, code)
		}
	}
}
