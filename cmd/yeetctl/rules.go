package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/scrubrules"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Mirrors of the analyzer's limits and rule state format
// (pkg/analyzer/rules.go, rules_persist.go). The analyzer stays the
// authority: these only let an operator catch mistakes before pushing.
const (
	ruleScopeSep        = "/"
	maxRuleSetBytes     = 3 << 20
	maxRuleStateBytes   = 8 * maxRuleSetBytes
	ruleStateFile       = "scrub-rules.json"
	defaultRuleStateDir = "/var/lib/packetyeeter"
	maxRuleFileBytes    = maxRuleStateBytes
)

type persistedRules struct {
	Version int                                   `json:"version"`
	Saved   time.Time                             `json:"saved"`
	Scopes  map[string]map[string]json.RawMessage `json:"scopes"`
}

func rulesCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "push":
			return rulesPushCmd(args[1:], stdout, stderr)
		case "diff":
			return rulesDiffCmd(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintln(stderr, "usage: yeetctl rules push [flags] <file|->")
	fmt.Fprintln(stderr, "       yeetctl rules diff [flags] <file|->")
	return 2
}

func rulesPushCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules push", flag.ContinueOnError)
	fs.SetOutput(stderr)
	af := addAnalyzerFlags(fs, true)
	scope := fs.String("scope", "", "Scope to push to; overrides the file's scope")
	dryRun := fs.Bool("dry-run", false, "Validate locally and print the RuleSet that would be sent, without calling the analyzer")
	allowEmpty := fs.Bool("allow-empty", false, "Allow a set without rules, which removes every rule of the scope")
	jsonOut := fs.Bool("json", false, "Print the PushRulesAck as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: yeetctl rules push [flags] <file|->")
		return 2
	}

	rs, err := loadRuleSet(fs.Arg(0), *scope)
	if err != nil {
		return exitCode(stderr, "rules push", err)
	}
	if err := validateRuleSet(rs, time.Now()); err != nil {
		return exitCode(stderr, "rules push", err)
	}
	if len(rs.GetRules()) == 0 && !*allowEmpty {
		return exitCode(stderr, "rules push", usageError{fmt.Sprintf(
			"the set has no rules, which removes every rule of scope %q; pass -allow-empty to do that", rs.GetScope())})
	}

	if *dryRun {
		fmt.Fprintf(stderr, "Dry run: would push %s to scope %q (not sent)\n", describeRules(rs.GetRules()), rs.GetScope())
		b, err := indentJSON(rs)
		if err != nil {
			return exitCode(stderr, "rules push", err)
		}
		stdout.Write(b)
		return 0
	}

	conn, err := af.dial(stderr)
	if err != nil {
		return exitCode(stderr, "rules push", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), af.timeout)
	defer cancel()
	ack, err := apiv1.NewAnalyzerServiceClient(conn).PushRules(ctx, rs)
	if err != nil {
		return exitCode(stderr, "rules push", rpcError("PushRules", err))
	}
	if *jsonOut {
		b, err := indentJSON(ack)
		if err != nil {
			return exitCode(stderr, "rules push", err)
		}
		stdout.Write(b)
		return 0
	}
	fmt.Fprintf(stdout, "Pushed %s to scope %q; %d scrub collector(s) were sent the set\n",
		describeRules(rs.GetRules()), rs.GetScope(), ack.GetCollectors())
	return 0
}

// rulesDiffCmd compares a rule file with the analyzer's persisted rule state.
// There is no RPC that returns the live rules; the state file is written on
// every accepted push when the analyzer runs with -rule-state-dir. It exits
// 0 when they match, 1 when they differ and 2 on errors.
func rulesDiffCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rules diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	scope := fs.String("scope", "", "Scope to compare; overrides the file's scope")
	stateDir := fs.String("rule-state-dir", defaultRuleStateDir, "The analyzer's -rule-state-dir, holding "+ruleStateFile)
	jsonOut := fs.Bool("json", false, "Print the difference as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: yeetctl rules diff [flags] <file|->")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "rules diff: %v\n", err)
		return 2
	}

	rs, err := loadRuleSet(fs.Arg(0), *scope)
	if err != nil {
		return fail(err)
	}
	now := time.Now()
	if err := validateRuleSet(rs, now); err != nil {
		return fail(err)
	}
	path := filepath.Join(*stateDir, ruleStateFile)
	current, saved, expired, err := loadPersistedScope(path, rs.GetScope(), now)
	if err != nil {
		return fail(err)
	}

	d := diffRules(current, rs.GetRules())
	if *jsonOut {
		if err := writeDiffJSON(stdout, rs.GetScope(), saved, expired, d); err != nil {
			return fail(err)
		}
	} else if err := writeDiffText(stdout, rs.GetScope(), path, saved, expired, d); err != nil {
		return fail(err)
	}
	if d.empty() {
		return 0
	}
	return 1
}

func loadRuleSet(path, scope string) (*apiv1.RuleSet, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxRuleFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxRuleFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxRuleFileBytes)
	}
	rs := &apiv1.RuleSet{}
	if err := protojson.Unmarshal(data, rs); err != nil {
		return nil, fmt.Errorf("parse %s as a RuleSet: %w", path, err)
	}
	if scope != "" {
		rs.Scope = scope
	}
	return rs, nil
}

// validateRuleSet applies the checks PushRules applies to one scope. Limits
// across all scopes can only be checked by the analyzer.
func validateRuleSet(rs *apiv1.RuleSet, now time.Time) error {
	scope := rs.GetScope()
	if scope == "" || strings.Contains(scope, ruleScopeSep) {
		return usageError{fmt.Sprintf("scope must be non-empty and must not contain %q (set it in the file or with -scope)", ruleScopeSep)}
	}
	parsed := make(map[string]*scrubrules.Rule, len(rs.GetRules()))
	size := 0
	for _, r := range rs.GetRules() {
		if _, err := scrubrules.Parse(r, now); err != nil {
			return err
		}
		w := proto.Clone(r).(*apiv1.Rule)
		w.Id = scope + ruleScopeSep + r.GetId()
		if _, dup := parsed[w.Id]; dup {
			return fmt.Errorf("rule %q appears twice", r.GetId())
		}
		p, err := scrubrules.Parse(w, now)
		if err != nil {
			return err
		}
		parsed[w.Id] = p
		size += proto.Size(w)
	}
	if err := scrubrules.CheckCapacity(parsed); err != nil {
		return err
	}
	if size > maxRuleSetBytes {
		return fmt.Errorf("rule set encodes to %d bytes, at most %d", size, maxRuleSetBytes)
	}
	return nil
}

func describeRules(rules []*apiv1.Rule) string {
	if len(rules) == 0 {
		return "0 rules (removes the scope)"
	}
	byAction := map[string]int{}
	for _, r := range rules {
		byAction[strings.TrimPrefix(r.GetAction().String(), "RULE_ACTION_")]++
	}
	actions := make([]string, 0, len(byAction))
	for a := range byAction {
		actions = append(actions, a)
	}
	sort.Strings(actions)
	parts := make([]string, 0, len(actions))
	for _, a := range actions {
		parts = append(parts, fmt.Sprintf("%d %s", byAction[a], a))
	}
	noun := "rules"
	if len(rules) == 1 {
		noun = "rule"
	}
	return fmt.Sprintf("%d %s (%s)", len(rules), noun, strings.Join(parts, ", "))
}

// loadPersistedScope returns the unexpired rules of scope in the analyzer's
// rule state file, keyed by id without the scope prefix. Expired rules are
// left out because the analyzer no longer sends them; their ids are returned.
func loadPersistedScope(path, scope string, now time.Time) (map[string]*apiv1.Rule, time.Time, []string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, time.Time{}, nil, fmt.Errorf("no rule state at %s: the analyzer writes it only with -rule-state-dir, after the first accepted push", path)
	}
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRuleStateBytes+1))
	if err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxRuleStateBytes {
		return nil, time.Time{}, nil, fmt.Errorf("%s is larger than %d bytes", path, maxRuleStateBytes)
	}
	var doc persistedRules
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, time.Time{}, nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if doc.Version != 1 {
		return nil, time.Time{}, nil, fmt.Errorf("%s: unsupported rule state version %d", path, doc.Version)
	}

	out := map[string]*apiv1.Rule{}
	var expired []string
	prefix := scope + ruleScopeSep
	for wireID, raw := range doc.Scopes[scope] {
		r := &apiv1.Rule{}
		if err := protojson.Unmarshal(raw, r); err != nil {
			return nil, time.Time{}, nil, fmt.Errorf("%s: rule %q: %w", path, wireID, err)
		}
		id, ok := strings.CutPrefix(wireID, prefix)
		if !ok || r.GetId() != wireID {
			return nil, time.Time{}, nil, fmt.Errorf("%s: rule %q does not belong to scope %q", path, wireID, scope)
		}
		if !now.Before(r.GetExpiresAt().AsTime()) {
			expired = append(expired, id)
			continue
		}
		r.Id = id
		out[id] = r
	}
	sort.Strings(expired)
	return out, doc.Saved, expired, nil
}

type ruleChange struct {
	ID  string
	Old *apiv1.Rule
	New *apiv1.Rule
}

type ruleDiff struct {
	Added     []*apiv1.Rule
	Removed   []*apiv1.Rule
	Changed   []ruleChange
	Unchanged int
}

func (d ruleDiff) empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

func diffRules(current map[string]*apiv1.Rule, desired []*apiv1.Rule) ruleDiff {
	var d ruleDiff
	seen := make(map[string]bool, len(desired))
	for _, r := range desired {
		seen[r.GetId()] = true
		old, ok := current[r.GetId()]
		switch {
		case !ok:
			d.Added = append(d.Added, r)
		case proto.Equal(old, r):
			d.Unchanged++
		default:
			d.Changed = append(d.Changed, ruleChange{ID: r.GetId(), Old: old, New: r})
		}
	}
	for id, r := range current {
		if !seen[id] {
			d.Removed = append(d.Removed, r)
		}
	}
	byID := func(rs []*apiv1.Rule) {
		sort.Slice(rs, func(i, j int) bool { return rs[i].GetId() < rs[j].GetId() })
	}
	byID(d.Added)
	byID(d.Removed)
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].ID < d.Changed[j].ID })
	return d
}

func writeDiffText(w io.Writer, scope, path string, saved time.Time, expired []string, d ruleDiff) error {
	fmt.Fprintf(w, "Scope %q: file vs %s (saved %s)\n", scope, path, saved.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "%d added, %d removed, %d changed, %d unchanged\n", len(d.Added), len(d.Removed), len(d.Changed), d.Unchanged)
	if len(expired) > 0 {
		fmt.Fprintf(w, "Ignored %d expired rule(s) in the state file: %s\n", len(expired), strings.Join(expired, ", "))
	}
	line := func(prefix string, r *apiv1.Rule) error {
		b, err := compactJSON(r)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s %s\n", prefix, b)
		return err
	}
	for _, r := range d.Added {
		if err := line("+", r); err != nil {
			return err
		}
	}
	for _, r := range d.Removed {
		if err := line("-", r); err != nil {
			return err
		}
	}
	for _, c := range d.Changed {
		fmt.Fprintf(w, "~ %s\n", c.ID)
		if err := line("  -", c.Old); err != nil {
			return err
		}
		if err := line("  +", c.New); err != nil {
			return err
		}
	}
	return nil
}

func writeDiffJSON(w io.Writer, scope string, saved time.Time, expired []string, d ruleDiff) error {
	raw := func(r *apiv1.Rule) (json.RawMessage, error) {
		b, err := compactJSON(r)
		return json.RawMessage(b), err
	}
	list := func(rs []*apiv1.Rule) ([]json.RawMessage, error) {
		out := make([]json.RawMessage, 0, len(rs))
		for _, r := range rs {
			b, err := raw(r)
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
		return out, nil
	}
	type change struct {
		ID  string          `json:"id"`
		Old json.RawMessage `json:"old"`
		New json.RawMessage `json:"new"`
	}
	doc := struct {
		Scope     string            `json:"scope"`
		Saved     time.Time         `json:"saved"`
		Added     []json.RawMessage `json:"added"`
		Removed   []json.RawMessage `json:"removed"`
		Changed   []change          `json:"changed"`
		Unchanged int               `json:"unchanged"`
		Expired   []string          `json:"expired_ignored"`
	}{Scope: scope, Saved: saved, Unchanged: d.Unchanged, Changed: []change{}, Expired: expired}
	if doc.Expired == nil {
		doc.Expired = []string{}
	}
	var err error
	if doc.Added, err = list(d.Added); err != nil {
		return err
	}
	if doc.Removed, err = list(d.Removed); err != nil {
		return err
	}
	for _, c := range d.Changed {
		o, err := raw(c.Old)
		if err != nil {
			return err
		}
		n, err := raw(c.New)
		if err != nil {
			return err
		}
		doc.Changed = append(doc.Changed, change{ID: c.ID, Old: o, New: n})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
