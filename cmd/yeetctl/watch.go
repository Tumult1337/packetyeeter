package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// watchCmd streams WatchDecisions until ctx ends (Ctrl-C), which exits 0.
func watchCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	af := addAnalyzerFlags(fs, false)
	subscriber := fs.String("subscriber", defaultSubscriber(), "Subscriber name the analyzer logs")
	jsonOut := fs.Bool("json", false, "Print each Decision as one line of JSON (NDJSON)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: yeetctl watch [flags]")
		return 2
	}

	conn, err := af.dial(stderr)
	if err != nil {
		return exitCode(stderr, "watch", err)
	}
	defer conn.Close()
	stream, err := apiv1.NewAnalyzerServiceClient(conn).WatchDecisions(ctx, &apiv1.WatchRequest{Subscriber: *subscriber})
	if err != nil {
		return watchEnd(ctx, stderr, err)
	}
	for {
		d, err := stream.Recv()
		if err != nil {
			return watchEnd(ctx, stderr, err)
		}
		var line []byte
		if *jsonOut {
			if line, err = compactJSON(d); err != nil {
				return exitCode(stderr, "watch", err)
			}
		} else {
			line = []byte(formatDecision(time.Now(), d))
		}
		line = append(line, '\n')
		if _, err := stdout.Write(line); err != nil {
			// A closed pipe (yeetctl watch | head) ends the watch quietly.
			return 0
		}
	}
}

func watchEnd(ctx context.Context, stderr io.Writer, err error) int {
	if errors.Is(err, io.EOF) || (ctx.Err() != nil && status.Code(err) == codes.Canceled) {
		return 0
	}
	return exitCode(stderr, "watch", rpcError("WatchDecisions", err))
}

func defaultSubscriber() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return "yeetctl@" + h
	}
	return "yeetctl"
}

// formatDecision renders one decision as a single line: receive time, kind,
// then key=value fields; empty fields are left out.
func formatDecision(now time.Time, d *apiv1.Decision) string {
	var b strings.Builder
	b.WriteString(now.UTC().Format(time.RFC3339))
	kv := func(k string, v any) { fmt.Fprintf(&b, " %s=%v", k, v) }
	switch k := d.GetKind().(type) {
	case *apiv1.Decision_Command:
		c := k.Command
		b.WriteString(" command ")
		b.WriteString(strings.TrimPrefix(c.GetType().String(), "COMMAND_"))
		if len(c.GetIp()) > 0 {
			kv("ip", ipString(c.GetIp()))
		}
		if c.GetCidr() != "" {
			kv("cidr", c.GetCidr())
		}
		if c.GetDurationSeconds() != 0 {
			kv("duration", time.Duration(c.GetDurationSeconds())*time.Second)
		}
		if c.GetSource() != "" {
			kv("source", c.GetSource())
		}
		if c.GetPriority() != 0 {
			kv("priority", c.GetPriority())
		}
		if r := c.GetRules(); r != nil {
			kv("rules_upsert", len(r.GetUpsert()))
			kv("rules_remove", len(r.GetRemove()))
			kv("replace", r.GetReplace())
		}
		if c.GetReason() != "" {
			fmt.Fprintf(&b, " reason=%q", c.GetReason())
		}
	case *apiv1.Decision_Campaign:
		c := k.Campaign
		b.WriteString(" campaign")
		kv("vector", c.GetVector())
		if c.GetProtocol() != 0 {
			kv("protocol", c.GetProtocol())
		}
		if c.GetDstPortBucket() != "" {
			kv("dst_port", c.GetDstPortBucket())
		}
		if c.GetDstPrefix() != "" {
			kv("dst_prefix", c.GetDstPrefix())
		}
		fmt.Fprintf(&b, " rate=%.1f/s", c.GetRatePps())
		if ts := c.GetObservedAt(); ts != nil {
			kv("observed", ts.AsTime().UTC().Format(time.RFC3339))
		}
	case *apiv1.Decision_Fingerprint:
		f := k.Fingerprint
		b.WriteString(" fingerprint")
		kv("collector", f.GetCollectorId())
		kv("dst", ipString(f.GetDstIp()))
		kv("protocol", f.GetProtocol())
		if f.GetDstPort() != 0 {
			kv("dst_port", f.GetDstPort())
		}
		kv("size_bucket", f.GetSizeBucket())
		kv("ttl_bucket", f.GetTtlBucket())
		kv("src_net", ipString(f.GetSrcNet()))
		kv("dropped", f.GetDropped())
		kv("packets", f.GetPackets())
		kv("bytes", f.GetBytes())
		kv("interval", time.Duration(f.GetIntervalSeconds())*time.Second)
	default:
		b.WriteString(" unknown")
	}
	return b.String()
}

func ipString(b []byte) string {
	if a, ok := netip.AddrFromSlice(b); ok {
		return a.Unmap().String()
	}
	return fmt.Sprintf("invalid(%x)", b)
}
