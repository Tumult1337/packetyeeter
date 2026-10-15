package metrics

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Metric names and label sets are part of the operator-facing compatibility
// surface (dashboards, alerts and recording rules depend on them). These
// tests pin them in testdata/metrics.golden so removals and renames fail CI.
//
// After intentionally adding a metric or label, regenerate the golden file:
//
//	go test ./pkg/metrics -run TestMetricNamesGolden -update-metrics-golden
//
// Removing or renaming a metric or label breaks dashboards and alerts; see
// docs/compatibility.md before doing so.

var updateMetricsGolden = flag.Bool("update-metrics-golden", false, "rewrite testdata/metrics.golden from the source tree")

const (
	metricsGoldenPath = "testdata/metrics.golden"
	repoRoot          = "../.."
	metricPrefix      = "packetyeeter_"
)

// Repository files whose packetyeeter_* references must resolve to a defined
// metric.
var dashboardFiles = []string{
	"grafana-dashboard.json",
	"grafana-dashboard.influx.json",
	"examples/prometheus-alerts.yml",
}

type metricDef struct {
	name   string
	kind   string
	labels []string
	pos    string
}

func (m metricDef) line() string {
	return fmt.Sprintf("%s %s [%s]", m.name, m.kind, strings.Join(m.labels, ","))
}

// constructorKinds maps prometheus/promauto constructor names to the metric
// kind recorded in the golden file. The bool reports whether the second
// argument is the variable label list.
var constructorKinds = map[string]struct {
	kind  string
	isVec bool
}{
	"NewCounter":      {"counter", false},
	"NewCounterVec":   {"counter", true},
	"NewCounterFunc":  {"counter", false},
	"NewGauge":        {"gauge", false},
	"NewGaugeVec":     {"gauge", true},
	"NewGaugeFunc":    {"gauge", false},
	"NewHistogram":    {"histogram", false},
	"NewHistogramVec": {"histogram", true},
	"NewSummary":      {"summary", false},
	"NewSummaryVec":   {"summary", true},
	"NewUntypedFunc":  {"untyped", false},
	"NewDesc":         {"desc", false},
}

// scanMetricDefinitions parses every non-test Go file in the repository and
// returns the packetyeeter_* metrics defined through prometheus/promauto
// constructors. Definitions whose name or labels are not literals are
// reported as errors so a refactor cannot silently drop a metric from the
// check.
func scanMetricDefinitions(t *testing.T) []metricDef {
	t.Helper()
	var defs []metricDef
	var problems []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != repoRoot && (strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || (pkg.Name != "prometheus" && pkg.Name != "promauto") {
				return true
			}
			ctor, ok := constructorKinds[sel.Sel.Name]
			if !ok || len(call.Args) == 0 {
				return true
			}
			pos := fset.Position(call.Pos()).String()

			var name string
			var labelsExpr ast.Expr
			if sel.Sel.Name == "NewDesc" {
				name, ok = stringLiteral(call.Args[0])
				if !ok {
					if containsPrefixLiteral(call.Args[0]) {
						problems = append(problems, pos+": NewDesc name is not a string literal")
					}
					return true
				}
				if len(call.Args) >= 3 {
					labelsExpr = call.Args[2]
				}
			} else {
				opts, ok := call.Args[0].(*ast.CompositeLit)
				if !ok {
					return true
				}
				nameExpr := compositeField(opts, "Name")
				if nameExpr == nil {
					return true
				}
				if compositeField(opts, "Namespace") != nil || compositeField(opts, "Subsystem") != nil {
					problems = append(problems, pos+": Namespace/Subsystem are not supported by the metrics compatibility scanner; use a full Name literal")
					return true
				}
				name, ok = stringLiteral(nameExpr)
				if !ok {
					if containsPrefixLiteral(nameExpr) {
						problems = append(problems, pos+": metric Name is not a string literal")
					}
					return true
				}
				if ctor.isVec && len(call.Args) >= 2 {
					labelsExpr = call.Args[1]
				}
			}
			if !strings.HasPrefix(name, metricPrefix) {
				return true
			}
			labels, ok := stringSliceLiteral(labelsExpr)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: labels for %s are not a []string literal or nil", pos, name))
				return true
			}
			defs = append(defs, metricDef{name: name, kind: ctor.kind, labels: labels, pos: pos})
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan metric definitions: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("metric definitions the compatibility scanner cannot read:\n  %s", strings.Join(problems, "\n  "))
	}
	return defs
}

func compositeField(lit *ast.CompositeLit, key string) ast.Expr {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == key {
			return kv.Value
		}
	}
	return nil
}

func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func containsPrefixLiteral(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(lit.Value, metricPrefix) {
			found = true
		}
		return !found
	})
	return found
}

// stringSliceLiteral returns the elements of a []string{...} literal. A
// missing or nil expression means no variable labels.
func stringSliceLiteral(e ast.Expr) ([]string, bool) {
	if e == nil {
		return nil, true
	}
	if id, ok := e.(*ast.Ident); ok && id.Name == "nil" {
		return nil, true
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		s, ok := stringLiteral(elt)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// canonicalMetricLines dedupes definitions by name and fails on two
// definitions of the same name with a different kind or label set.
func canonicalMetricLines(t *testing.T, defs []metricDef) []string {
	t.Helper()
	byName := map[string]metricDef{}
	for _, d := range defs {
		if prev, ok := byName[d.name]; ok && prev.line() != d.line() {
			t.Fatalf("metric %s defined inconsistently:\n  %s: %s\n  %s: %s", d.name, prev.pos, prev.line(), d.pos, d.line())
		}
		byName[d.name] = d
	}
	lines := make([]string, 0, len(byName))
	for _, d := range byName {
		lines = append(lines, d.line())
	}
	sort.Strings(lines)
	return lines
}

func readGolden(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(metricsGoldenPath)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update-metrics-golden to create it)", metricsGoldenPath, err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

const goldenHeader = `# Generated by: go test ./pkg/metrics -run TestMetricNamesGolden -update-metrics-golden
# One line per metric: <name> <kind> [<variable labels>]. Removing or renaming
# a metric or label breaks dashboards and alerts; see docs/compatibility.md.
`

func TestMetricNamesGolden(t *testing.T) {
	got := canonicalMetricLines(t, scanMetricDefinitions(t))
	if len(got) == 0 {
		t.Fatal("found no packetyeeter_* metric definitions; scanner is broken")
	}

	if *updateMetricsGolden {
		if err := os.MkdirAll(filepath.Dir(metricsGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(metricsGoldenPath, []byte(goldenHeader+strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want := readGolden(t)
	gotSet := toSet(got)
	wantSet := toSet(want)

	var removed, added []string
	for _, l := range want {
		if !gotSet[l] {
			removed = append(removed, l)
		}
	}
	for _, l := range got {
		if !wantSet[l] {
			added = append(added, l)
		}
	}
	if len(removed) > 0 {
		t.Errorf("metrics removed or changed (name, kind or labels) compared with %s; this breaks dashboards and alerts, see docs/compatibility.md:\n  - %s",
			metricsGoldenPath, strings.Join(removed, "\n  - "))
	}
	if len(added) > 0 {
		t.Errorf("new or changed metrics are not in %s; if intended, regenerate it with -update-metrics-golden:\n  + %s",
			metricsGoldenPath, strings.Join(added, "\n  + "))
	}
}

var dashboardMetricPattern = regexp.MustCompile(`packetyeeter_[a-zA-Z0-9_]+`)

// TestDashboardMetricsExist checks that every packetyeeter_* metric the
// bundled Grafana dashboards and example alert rules query is still defined.
func TestDashboardMetricsExist(t *testing.T) {
	defs := scanMetricDefinitions(t)
	kinds := map[string]string{}
	for _, d := range defs {
		kinds[d.name] = d.kind
	}

	for _, file := range dashboardFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.HasSuffix(file, ".json") && !json.Valid(data) {
			t.Errorf("%s is not valid JSON", file)
			continue
		}
		seen := map[string]bool{}
		for _, name := range dashboardMetricPattern.FindAllString(string(data), -1) {
			if seen[name] {
				continue
			}
			seen[name] = true
			if !dashboardMetricDefined(name, kinds) {
				t.Errorf("%s references undefined metric %s", file, name)
			}
		}
		if len(seen) == 0 {
			t.Errorf("%s references no packetyeeter_* metrics; check the pattern", file)
		}
	}
}

func dashboardMetricDefined(name string, kinds map[string]string) bool {
	if _, ok := kinds[name]; ok {
		return true
	}
	for _, suffix := range []string{"_bucket", "_sum", "_count"} {
		base, ok := strings.CutSuffix(name, suffix)
		if !ok {
			continue
		}
		switch kinds[base] {
		case "histogram", "summary":
			if suffix != "_bucket" || kinds[base] == "histogram" {
				return true
			}
		}
	}
	return false
}

func toSet(lines []string) map[string]bool {
	set := make(map[string]bool, len(lines))
	for _, l := range lines {
		set[l] = true
	}
	return set
}
