package analyzer

import (
	"context"
	"testing"

	"PacketYeeter/pkg/buildinfo"

	"google.golang.org/protobuf/types/known/emptypb"
)

func TestHealthReportsState(t *testing.T) {
	a := newRuleAnalyzer(t)
	addCollector(t, a, "scrub")
	addCollector(t, a, "")

	resp, err := a.Health(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !resp.GetHealthy() {
		t.Fatal("running analyzer reported unhealthy")
	}
	if resp.GetVersion() != buildinfo.Version {
		t.Fatalf("version = %q, want %q", resp.GetVersion(), buildinfo.Version)
	}
	if !resp.GetUptimeSince().AsTime().Equal(a.startTime) {
		t.Fatalf("uptime_since = %v, want %v", resp.GetUptimeSince().AsTime(), a.startTime)
	}
	want := map[string]string{
		"enforcement": "enforcing",
		"collectors":  "2 connected (1 scrub)",
		"rule_api":    "enabled",
		"watch_api":   "disabled",
	}
	for k, v := range want {
		if got := resp.GetComponents()[k]; got != v {
			t.Errorf("components[%q] = %q, want %q", k, got, v)
		}
	}
}

func TestHealthEnforcementModes(t *testing.T) {
	a := newTestAnalyzer(t)
	a.Config.DryRun = true
	resp, _ := a.Health(context.Background(), &emptypb.Empty{})
	if got := resp.GetComponents()["enforcement"]; got != "dry-run" {
		t.Fatalf("dry-run enforcement = %q", got)
	}

	a.Config.DryRun = false
	a.enforcement.Stop("test")
	resp, _ = a.Health(context.Background(), &emptypb.Empty{})
	if got := resp.GetComponents()["enforcement"]; got != "stopped" {
		t.Fatalf("stopped enforcement = %q", got)
	}

	a.cancel()
	resp, _ = a.Health(context.Background(), &emptypb.Empty{})
	if resp.GetHealthy() {
		t.Fatal("shutting-down analyzer reported healthy")
	}
}
