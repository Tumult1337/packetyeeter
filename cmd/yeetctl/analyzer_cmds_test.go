package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeAnalyzer struct {
	apiv1.UnimplementedAnalyzerServiceServer

	health    *apiv1.HealthResponse
	pushErr   error
	decisions []*apiv1.Decision

	mu         sync.Mutex
	pushed     []*apiv1.RuleSet
	subscriber string
	watching   chan struct{} // closed once WatchDecisions sent everything
}

func (f *fakeAnalyzer) Health(context.Context, *emptypb.Empty) (*apiv1.HealthResponse, error) {
	if f.health == nil {
		return nil, status.Error(codes.Unimplemented, "method Health not implemented")
	}
	return f.health, nil
}

func (f *fakeAnalyzer) PushRules(_ context.Context, rs *apiv1.RuleSet) (*apiv1.PushRulesAck, error) {
	if f.pushErr != nil {
		return nil, f.pushErr
	}
	f.mu.Lock()
	f.pushed = append(f.pushed, rs)
	f.mu.Unlock()
	return &apiv1.PushRulesAck{Collectors: 2}, nil
}

func (f *fakeAnalyzer) WatchDecisions(req *apiv1.WatchRequest, stream apiv1.AnalyzerService_WatchDecisionsServer) error {
	f.mu.Lock()
	f.subscriber = req.GetSubscriber()
	f.mu.Unlock()
	for _, d := range f.decisions {
		if err := stream.Send(d); err != nil {
			return err
		}
	}
	close(f.watching)
	<-stream.Context().Done()
	return status.FromContextError(stream.Context().Err()).Err()
}

func (f *fakeAnalyzer) pushedSets() []*apiv1.RuleSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*apiv1.RuleSet(nil), f.pushed...)
}

// serve starts impl on an in-process listener and points yeetctl's dialer at it.
func serve(t *testing.T, impl apiv1.AnalyzerServiceServer) {
	t.Helper()
	if f, ok := impl.(*fakeAnalyzer); ok && f.watching == nil {
		f.watching = make(chan struct{})
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	apiv1.RegisterAnalyzerServiceServer(srv, impl)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	prev := extraDialOptions
	extraDialOptions = []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	t.Cleanup(func() { extraDialOptions = prev })
}

var bufArgs = []string{"-analyzer-addr", "passthrough:///bufnet", "-timeout", "5s"}

func run(fn func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := fn(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func health(args []string, o, e *bytes.Buffer) int   { return healthCmd(args, o, e) }
func rulesCLI(args []string, o, e *bytes.Buffer) int { return rulesCmd(args, o, e) }
func withBuf(args ...string) []string                { return append(append([]string{}, bufArgs...), args...) }
func pushArgs(args ...string) []string               { return append([]string{"push"}, withBuf(args...)...) }
func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHealthCommand(t *testing.T) {
	since := time.Now().Add(-90 * time.Minute)
	serve(t, &fakeAnalyzer{health: &apiv1.HealthResponse{
		Healthy:     true,
		Version:     "v1.2.3",
		UptimeSince: timestamppb.New(since),
		Components:  map[string]string{"enforcement": "dry-run", "collectors": "3 connected (1 scrub)"},
	}})

	code, out, errOut := run(health, withBuf()...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"(healthy)", "Version:   v1.2.3", "Up since:  " + since.UTC().Format(time.RFC3339), "enforcement  dry-run", "collectors   3 connected (1 scrub)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	code, out, _ = run(health, withBuf("-json")...)
	if code != 0 {
		t.Fatalf("json exit %d", code)
	}
	var got apiv1.HealthResponse
	if err := protojson.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if got.GetVersion() != "v1.2.3" || got.GetComponents()["enforcement"] != "dry-run" {
		t.Fatalf("json output = %v", &got)
	}
}

func TestHealthCommandUnhealthyAndErrors(t *testing.T) {
	serve(t, &fakeAnalyzer{health: &apiv1.HealthResponse{Healthy: false}})
	if code, out, _ := run(health, withBuf()...); code != 1 || !strings.Contains(out, "UNHEALTHY") {
		t.Fatalf("unhealthy: exit %d, output %q", code, out)
	}

	serve(t, &fakeAnalyzer{})
	code, _, errOut := run(health, withBuf()...)
	if code != 1 || !strings.Contains(errOut, "does not implement") {
		t.Fatalf("unimplemented: exit %d, stderr %q", code, errOut)
	}

	code, _, errOut = run(health, withBuf("-analyzer-tls-cert", "c.pem")...)
	if code != 1 || !strings.Contains(errOut, "-analyzer-tls-cert requires -analyzer-tls-key") {
		t.Fatalf("bad tls flags: exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := run(health, withBuf("extra")...); code != 2 {
		t.Fatalf("extra argument: exit %d, want 2", code)
	}
}

func ruleSetJSON(scope string, expires time.Time, rules ...string) string {
	return `{"scope":"` + scope + `","rules":[` + strings.Join(rules, ",") + `]}`
}

func dropRule(id, prefix string, expires time.Time) string {
	return `{"id":"` + id + `","dstPrefix":"` + prefix + `","protocols":[17],"dstPorts":[{"from":53,"to":53}],"action":"RULE_ACTION_DROP","expiresAt":"` + expires.UTC().Format(time.RFC3339) + `"}`
}

func passRule(id, prefix string, expires time.Time) string {
	return `{"id":"` + id + `","dstPrefix":"` + prefix + `","action":"RULE_ACTION_PASS","expiresAt":"` + expires.UTC().Format(time.RFC3339) + `"}`
}

func TestRulesPush(t *testing.T) {
	f := &fakeAnalyzer{}
	serve(t, f)
	exp := time.Now().Add(time.Hour)
	file := writeFile(t, "rules.json", ruleSetJSON("ctl", exp, dropRule("dns", "192.0.2.0/24", exp), passRule("ok", "2001:db8::/64", exp)))

	code, out, errOut := run(rulesCLI, pushArgs(file)...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if want := `Pushed 2 rules (1 DROP, 1 PASS) to scope "ctl"; 2 scrub collector(s)`; !strings.Contains(out, want) {
		t.Fatalf("output %q missing %q", out, want)
	}
	sets := f.pushedSets()
	if len(sets) != 1 || sets[0].GetScope() != "ctl" || len(sets[0].GetRules()) != 2 || sets[0].GetRules()[0].GetId() != "dns" {
		t.Fatalf("pushed %v", sets)
	}

	code, out, _ = run(rulesCLI, pushArgs("-json", "-scope", "other", file)...)
	if code != 0 {
		t.Fatalf("json exit %d", code)
	}
	var ack apiv1.PushRulesAck
	if err := protojson.Unmarshal([]byte(out), &ack); err != nil || ack.GetCollectors() != 2 {
		t.Fatalf("ack %q: %v", out, err)
	}
	if got := f.pushedSets()[1].GetScope(); got != "other" {
		t.Fatalf("-scope not applied: %q", got)
	}
}

func TestRulesPushDryRunDoesNotCallAnalyzer(t *testing.T) {
	f := &fakeAnalyzer{}
	serve(t, f)
	exp := time.Now().Add(time.Hour)
	file := writeFile(t, "rules.json", ruleSetJSON("ctl", exp, dropRule("dns", "192.0.2.0/24", exp)))

	code, out, errOut := run(rulesCLI, pushArgs("-dry-run", file)...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(errOut, `would push 1 rule (1 DROP) to scope "ctl" (not sent)`) {
		t.Fatalf("stderr %q", errOut)
	}
	var rs apiv1.RuleSet
	if err := protojson.Unmarshal([]byte(out), &rs); err != nil || rs.GetRules()[0].GetId() != "dns" {
		t.Fatalf("dry-run output %q: %v", out, err)
	}
	if n := len(f.pushedSets()); n != 0 {
		t.Fatalf("dry run pushed %d sets", n)
	}
}

func TestRulesPushRejectsInvalidLocally(t *testing.T) {
	f := &fakeAnalyzer{}
	serve(t, f)
	exp := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	cases := map[string]struct {
		body string
		want string
		code int
	}{
		"no scope":       {ruleSetJSON("", exp, dropRule("a", "192.0.2.0/24", exp)), "scope must be non-empty", 2},
		"slash in scope": {ruleSetJSON("a/b", exp, dropRule("a", "192.0.2.0/24", exp)), "scope must be non-empty", 2},
		"expired":        {ruleSetJSON("ctl", exp, dropRule("a", "192.0.2.0/24", past)), "already expired", 1},
		"bad prefix":     {ruleSetJSON("ctl", exp, dropRule("a", "192.0.2.0/99", exp)), "dst_prefix", 1},
		"duplicate":      {ruleSetJSON("ctl", exp, dropRule("a", "192.0.2.0/24", exp), passRule("a", "198.51.100.0/24", exp)), "appears twice", 1},
		"unknown field":  {`{"scope":"ctl","rulez":[]}`, "parse", 1},
		"empty":          {ruleSetJSON("ctl", exp), "-allow-empty", 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			file := writeFile(t, "rules.json", tc.body)
			code, _, errOut := run(rulesCLI, pushArgs(file)...)
			if code != tc.code || !strings.Contains(errOut, tc.want) {
				t.Fatalf("exit %d (want %d), stderr %q (want %q)", code, tc.code, errOut, tc.want)
			}
		})
	}
	if n := len(f.pushedSets()); n != 0 {
		t.Fatalf("invalid sets reached the analyzer: %d", n)
	}

	file := writeFile(t, "empty.json", ruleSetJSON("ctl", exp))
	if code, out, errOut := run(rulesCLI, pushArgs("-allow-empty", file)...); code != 0 || !strings.Contains(out, "0 rules (removes the scope)") {
		t.Fatalf("-allow-empty: exit %d, out %q, stderr %q", code, out, errOut)
	}
}

func TestRulesPushReportsAnalyzerError(t *testing.T) {
	serve(t, &fakeAnalyzer{pushErr: status.Error(codes.PermissionDenied, "rule API disabled; start the analyzer with -enable-rule-api")})
	exp := time.Now().Add(time.Hour)
	file := writeFile(t, "rules.json", ruleSetJSON("ctl", exp, dropRule("dns", "192.0.2.0/24", exp)))
	code, _, errOut := run(rulesCLI, pushArgs(file)...)
	if code != 1 || !strings.Contains(errOut, "PermissionDenied") || !strings.Contains(errOut, "-enable-rule-api") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

// writeState writes rule state the way pkg/analyzer/rules_persist.go does:
// wire ids "<scope>/<id>" mapping to protojson rules carrying that id.
func writeState(t *testing.T, scopes map[string][]string) string {
	t.Helper()
	doc := persistedRules{Version: 1, Saved: time.Now().UTC(), Scopes: map[string]map[string]json.RawMessage{}}
	for scope, rules := range scopes {
		set := map[string]json.RawMessage{}
		for _, body := range rules {
			r := &apiv1.Rule{}
			if err := protojson.Unmarshal([]byte(body), r); err != nil {
				t.Fatal(err)
			}
			r.Id = scope + "/" + r.GetId()
			b, err := protojson.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			set[r.GetId()] = b
		}
		doc.Scopes[scope] = set
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ruleStateFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRulesDiff(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	later := exp.Add(time.Hour)
	past := time.Now().Add(-time.Minute)
	dir := writeState(t, map[string][]string{
		"ctl": {
			dropRule("same", "192.0.2.0/24", exp),
			dropRule("changed", "198.51.100.0/24", exp),
			passRule("gone", "203.0.113.0/24", exp),
			passRule("stale", "203.0.113.0/25", past),
		},
		"other": {passRule("theirs", "192.0.2.0/24", exp)},
	})
	file := writeFile(t, "rules.json", ruleSetJSON("ctl", exp,
		dropRule("same", "192.0.2.0/24", exp),
		dropRule("changed", "198.51.100.0/24", later),
		passRule("new", "2001:db8::/64", exp),
	))

	code, out, errOut := run(rulesCLI, "diff", "-rule-state-dir", dir, file)
	if code != 1 {
		t.Fatalf("exit %d (want 1 for differences), stderr %q", code, errOut)
	}
	for _, want := range []string{
		"1 added, 1 removed, 1 changed, 1 unchanged",
		"Ignored 1 expired rule(s) in the state file: stale",
		`+ {"id":"new"`,
		`- {"id":"gone"`,
		"~ changed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "theirs") {
		t.Errorf("diff leaked another scope:\n%s", out)
	}

	code, out, _ = run(rulesCLI, "diff", "-json", "-rule-state-dir", dir, file)
	if code != 1 {
		t.Fatalf("json exit %d", code)
	}
	var doc struct {
		Added     []map[string]any `json:"added"`
		Removed   []map[string]any `json:"removed"`
		Changed   []struct{ ID string }
		Unchanged int      `json:"unchanged"`
		Expired   []string `json:"expired_ignored"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(doc.Added) != 1 || doc.Added[0]["id"] != "new" || len(doc.Removed) != 1 || len(doc.Changed) != 1 || doc.Changed[0].ID != "changed" || doc.Unchanged != 1 || len(doc.Expired) != 1 {
		t.Fatalf("json diff = %+v", doc)
	}

	same := writeFile(t, "same.json", ruleSetJSON("other", exp, passRule("theirs", "192.0.2.0/24", exp)))
	if code, out, errOut := run(rulesCLI, "diff", "-rule-state-dir", dir, same); code != 0 || !strings.Contains(out, "0 added, 0 removed, 0 changed, 1 unchanged") {
		t.Fatalf("identical: exit %d, out %q, stderr %q", code, out, errOut)
	}
}

func TestRulesDiffErrors(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	file := writeFile(t, "rules.json", ruleSetJSON("ctl", exp, dropRule("a", "192.0.2.0/24", exp)))
	code, _, errOut := run(rulesCLI, "diff", "-rule-state-dir", t.TempDir(), file)
	if code != 2 || !strings.Contains(errOut, "-rule-state-dir") {
		t.Fatalf("missing state: exit %d, stderr %q", code, errOut)
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ruleStateFile), []byte(`{"version":2}`), 0o600)
	if code, _, errOut := run(rulesCLI, "diff", "-rule-state-dir", dir, file); code != 2 || !strings.Contains(errOut, "version 2") {
		t.Fatalf("bad version: exit %d, stderr %q", code, errOut)
	}
	if code, _, _ := run(rulesCLI, "bogus"); code != 2 {
		t.Fatalf("unknown rules subcommand: exit %d", code)
	}
}

func TestWatch(t *testing.T) {
	cmd := &apiv1.Command{
		Type: apiv1.CommandType_COMMAND_BLOCK_IP, Ip: []byte{192, 0, 2, 7},
		DurationSeconds: 300, Reason: "rate limit", Source: "analyzer",
	}
	fp := &apiv1.ScrubFingerprint{
		CollectorId: "peer#1", DstIp: netipBytes("2001:db8::1"), Protocol: 17, DstPort: 53,
		SizeBucket: 2, TtlBucket: 1, SrcNet: netipBytes("2001:db8:1::"), Dropped: true,
		Packets: 10, Bytes: 4000, IntervalSeconds: 10,
	}
	camp := &apiv1.CampaignObservation{Vector: "udp_flood", Protocol: 17, DstPrefix: "192.0.2.0/24", RatePps: 12.5}
	decisions := []*apiv1.Decision{
		{Kind: &apiv1.Decision_Command{Command: cmd}},
		{Kind: &apiv1.Decision_Fingerprint{Fingerprint: fp}},
		{Kind: &apiv1.Decision_Campaign{Campaign: camp}},
	}

	for _, jsonOut := range []bool{false, true} {
		f := &fakeAnalyzer{decisions: decisions}
		serve(t, f)
		args := []string{"-analyzer-addr", "passthrough:///bufnet", "-subscriber", "test"}
		if jsonOut {
			args = append(args, "-json")
		}
		ctx, cancel := context.WithCancel(context.Background())
		var out, errOut lockedBuffer
		done := make(chan int)
		go func() { done <- watchCmd(ctx, args, &out, &errOut) }()

		select {
		case <-f.watching:
		case code := <-done:
			cancel()
			t.Fatalf("watch exited early with %d: %s", code, errOut.String())
		case <-time.After(5 * time.Second):
			t.Fatal("watch never subscribed")
		}
		// Give the client time to print what the server sent before the
		// simulated Ctrl-C.
		waitFor(t, func() bool { return strings.Count(out.String(), "\n") >= len(decisions) })
		cancel()
		if code := <-done; code != 0 {
			t.Fatalf("json=%v: exit %d after cancel, stderr %q", jsonOut, code, errOut.String())
		}
		f.mu.Lock()
		sub := f.subscriber
		f.mu.Unlock()
		if sub != "test" {
			t.Fatalf("subscriber = %q", sub)
		}

		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != len(decisions) {
			t.Fatalf("json=%v: %d lines:\n%s", jsonOut, len(lines), out.String())
		}
		if jsonOut {
			for i, line := range lines {
				var d apiv1.Decision
				if err := protojson.Unmarshal([]byte(line), &d); err != nil {
					t.Fatalf("line %d is not a Decision: %v\n%s", i, err, line)
				}
				if !proto.Equal(&d, decisions[i]) {
					t.Fatalf("line %d = %v, want %v", i, &d, decisions[i])
				}
			}
			continue
		}
		for i, want := range []string{
			` command BLOCK_IP ip=192.0.2.7 duration=5m0s source=analyzer reason="rate limit"`,
			` fingerprint collector=peer#1 dst=2001:db8::1 protocol=17 dst_port=53 size_bucket=2 ttl_bucket=1 src_net=2001:db8:1:: dropped=true packets=10 bytes=4000 interval=10s`,
			` campaign vector=udp_flood protocol=17 dst_prefix=192.0.2.0/24 rate=12.5/s`,
		} {
			if !strings.HasSuffix(lines[i], want) {
				t.Errorf("line %d = %q, want suffix %q", i, lines[i], want)
			}
		}
	}
}

func TestWatchReportsServerError(t *testing.T) {
	serve(t, deniedWatch{})
	var out, errOut bytes.Buffer
	code := watchCmd(context.Background(), []string{"-analyzer-addr", "passthrough:///bufnet"}, &out, &errOut)
	if code != 1 || !strings.Contains(errOut.String(), "-enable-watch-api") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}

type deniedWatch struct {
	apiv1.UnimplementedAnalyzerServiceServer
}

func (deniedWatch) WatchDecisions(*apiv1.WatchRequest, apiv1.AnalyzerService_WatchDecisionsServer) error {
	return status.Error(codes.PermissionDenied, "WatchDecisions is disabled; start the analyzer with -enable-watch-api")
}

func netipBytes(s string) []byte {
	ip := net.ParseIP(s)
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// lockedBuffer is written by the watch goroutine while the test polls it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
