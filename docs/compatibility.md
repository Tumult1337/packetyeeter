# Compatibility surface

PacketYeeter is deployed as separately upgraded collectors and analyzers, and
operators build dashboards, alerts, HAProxy configs and automation around it.
This page lists what counts as the stable, operator-facing surface and how
changes to it are checked. Anything not listed here is internal and may change
without notice.

## Stable surface

| Surface | Where it is defined | How it is protected |
| --- | --- | --- |
| gRPC API `packetyeeter.v1` | `api/proto/v1/packetyeeter.proto` | `buf lint` and `buf breaking` in CI (`make proto-lint`, `make proto-breaking`) |
| Prometheus metric names, kinds and label names | `pkg/metrics`, `pkg/analyzer/reputation` | `TestMetricNamesGolden` against `pkg/metrics/testdata/metrics.golden` |
| Metrics used by the bundled dashboards | `grafana-dashboard.json`, `grafana-dashboard.influx.json` | `TestDashboardMetricsExist` |
| `/metrics` and collector `/readyz` HTTP endpoints | collector and analyzer metrics listeners | review |
| Inspector HTTP `/api/*` routes and JSON fields | `pkg/analyzer/inspect_*.go`, [`docs/api.md`](api.md) | review |
| CLI flags and environment variables | `cmd/*/main.go`, `packetyeeter-*.default`, `packetyeeter-*.service` | review |
| Collector management socket commands used by `yeetctl` | `pkg/collector`, `cmd/yeetctl` | review |
| Persisted state formats (scrub rule state in `-rule-state-dir`, JA4DB cache, AI/ASN state, allowlist and learned patterns, ML model state) | `pkg/analyzer`, `pkg/ml` | review |
| eBPF C/Go shared struct layouts (map keys/values, perf events) | `pkg/collector/ebpf/c/protector.bpf.c`, `pkg/collector/ebpf/types.go` | `TestTypesMatchCLayout` and existing layout tests in `pkg/collector/ebpf` |
| HAProxy SPOE agent, message, argument and variable names | `examples/packetyeeter.spoe.conf`, `pkg/collector/haproxy/spoe` | HAProxy e2e tests (`make e2e-test`) |

Go packages under `pkg/` are importable, but their Go APIs are **not** a
supported compatibility surface; they exist to build the PacketYeeter
binaries. Existing `pkg/` packages are not moved to avoid breaking importers.
New code that has no reason to be imported from outside the repository may be
placed under `internal/`.

## Rules for changes

- **Additive changes are fine.** New metrics, labels on new metrics, proto
  fields, RPCs, flags, routes and JSON fields do not break anyone. New proto
  fields must have a safe zero value, because older peers will not send them.
- **Do not remove or rename** anything in the table above in a normal change.
  Deprecate first (document it in `CHANGELOG.md`, keep the old name working)
  and remove it in a later, announced release.
- **Protobuf field and enum numbers are never reused or changed.** To retire a
  field, mark it `[deprecated = true]`. If it must be deleted, add its number
  and name to a `reserved` statement in the same message. Incompatible changes
  need a new package (`packetyeeter.v2`). The v1 API predates `buf lint`, so
  rules that would require renaming existing messages, RPC types or enum
  values are disabled in `api/proto/buf.yaml`; new definitions should still
  follow buf's standard naming.
- **Metric changes** (new metric, changed label set, removal) make
  `TestMetricNamesGolden` fail. For an intended addition, regenerate the
  golden file and commit it with the change:

  ```bash
  go test ./pkg/metrics -run TestMetricNamesGolden -update-metrics-golden
  ```

  Removing or renaming a metric or label also needs dashboard, alert
  (`examples/prometheus-alerts.yml`) and `docs/observability.md` updates.
  Metric names must be string literals in `Name:` or `prometheus.NewDesc` so
  the golden test can see them.
- **eBPF struct changes** must update the C struct, the Go mirror and the
  expected sizes/offsets in `pkg/collector/ebpf/layout_test.go` together.
  Collector and eBPF object are always shipped together, but the Go side must
  decode exactly what the kernel side writes.

## Checks

```bash
make proto-lint
make proto-breaking                    # against origin/main
make proto-breaking PROTO_AGAINST_REF=<git ref>
go test ./pkg/metrics ./pkg/collector/ebpf
```

`make portable-test` includes the metrics and eBPF layout tests. CI runs
`buf breaking` against the pull request base commit (or, on pushes to `main`,
the previous `main` commit).
