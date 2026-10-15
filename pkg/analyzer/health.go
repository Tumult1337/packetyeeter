package analyzer

import (
	"context"
	"fmt"

	apiv1 "PacketYeeter/api/proto/v1"
	"PacketYeeter/pkg/buildinfo"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Health reports whether the analyzer is serving and a few coarse state
// fields for operators. It is not a control-plane RPC, so it is answered for
// every client that can connect; keep it free of addresses and reasons.
func (a *Analyzer) Health(context.Context, *emptypb.Empty) (*apiv1.HealthResponse, error) {
	enforcement := "enforcing"
	if a.Config.DryRun {
		enforcement = "dry-run"
	} else if stopped, _ := a.enforcement.Status(); stopped {
		enforcement = "stopped"
	}

	a.collectorsMu.RLock()
	total, scrub := len(a.collectors), 0
	for _, cs := range a.collectors {
		if cs.isScrub() {
			scrub++
		}
	}
	a.collectorsMu.RUnlock()

	enabled := func(on bool) string {
		if on {
			return "enabled"
		}
		return "disabled"
	}
	return &apiv1.HealthResponse{
		Healthy:     a.lifetime().Err() == nil,
		Version:     buildinfo.Version,
		UptimeSince: timestamppb.New(a.startTime),
		Components: map[string]string{
			"enforcement": enforcement,
			"collectors":  fmt.Sprintf("%d connected (%d scrub)", total, scrub),
			"rule_api":    enabled(a.Config.EnableRuleAPI),
			"watch_api":   enabled(a.watch != nil),
		},
	}, nil
}
