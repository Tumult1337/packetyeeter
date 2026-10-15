package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/protobuf/types/known/emptypb"
)

// healthCmd exits 0 when the analyzer reports healthy, 1 when it reports
// unhealthy or cannot be asked, and 2 on usage errors.
func healthCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	af := addAnalyzerFlags(fs, true)
	jsonOut := fs.Bool("json", false, "Print the HealthResponse as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: yeetctl health [flags]")
		return 2
	}

	conn, err := af.dial(stderr)
	if err != nil {
		return exitCode(stderr, "health", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), af.timeout)
	defer cancel()
	resp, err := apiv1.NewAnalyzerServiceClient(conn).Health(ctx, &emptypb.Empty{})
	if err != nil {
		return exitCode(stderr, "health", rpcError("Health", err))
	}

	if *jsonOut {
		b, err := indentJSON(resp)
		if err != nil {
			return exitCode(stderr, "health", err)
		}
		stdout.Write(b)
	} else {
		printHealth(stdout, af.addr, resp, time.Now())
	}
	if !resp.GetHealthy() {
		return 1
	}
	return 0
}

func printHealth(w io.Writer, addr string, resp *apiv1.HealthResponse, now time.Time) {
	state := "healthy"
	if !resp.GetHealthy() {
		state = "UNHEALTHY"
	}
	fmt.Fprintf(w, "Analyzer:  %s (%s)\n", addr, state)
	if v := resp.GetVersion(); v != "" {
		fmt.Fprintf(w, "Version:   %s\n", v)
	}
	if ts := resp.GetUptimeSince(); ts != nil {
		since := ts.AsTime().UTC()
		fmt.Fprintf(w, "Up since:  %s (%s)\n", since.Format(time.RFC3339), now.Sub(since).Truncate(time.Second))
	}
	comps := resp.GetComponents()
	if len(comps) == 0 {
		return
	}
	names := make([]string, 0, len(comps))
	width := 0
	for k := range comps {
		names = append(names, k)
		width = max(width, len(k))
	}
	sort.Strings(names)
	fmt.Fprintln(w, "Components:")
	for _, k := range names {
		fmt.Fprintf(w, "  %-*s  %s\n", width, k, comps[k])
	}
}
