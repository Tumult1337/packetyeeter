package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"PacketYeeter/pkg/grpctls"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const defaultAnalyzerAddr = "127.0.0.1:9090"

// extraDialOptions lets tests dial an in-process server.
var extraDialOptions []grpc.DialOption

// analyzerFlags are the analyzer connection flags, named like the collector's.
type analyzerFlags struct {
	addr    string
	tls     grpctls.ClientConfig
	timeout time.Duration
}

func addAnalyzerFlags(fs *flag.FlagSet, withTimeout bool) *analyzerFlags {
	f := &analyzerFlags{}
	fs.StringVar(&f.addr, "analyzer-addr", defaultAnalyzerAddr, "Analyzer gRPC address")
	fs.StringVar(&f.tls.CAFile, "analyzer-tls-ca", "", "PEM CA bundle that verifies the analyzer's certificate; enables TLS")
	fs.StringVar(&f.tls.CertFile, "analyzer-tls-cert", "", "PEM client certificate for mTLS to the analyzer (requires -analyzer-tls-key and -analyzer-tls-ca)")
	fs.StringVar(&f.tls.KeyFile, "analyzer-tls-key", "", "PEM private key for -analyzer-tls-cert")
	fs.StringVar(&f.tls.ServerName, "analyzer-tls-server-name", "", "Name to verify in the analyzer's certificate (default: host part of -analyzer-addr)")
	if withTimeout {
		fs.DurationVar(&f.timeout, "timeout", 15*time.Second, "Deadline for the RPC")
	}
	return f
}

func (f *analyzerFlags) dial(stderr io.Writer) (*grpc.ClientConn, error) {
	log := logrus.New()
	log.SetOutput(stderr)
	log.SetLevel(logrus.WarnLevel)
	creds, err := grpctls.NewClientCredentials(f.tls, log)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		// The analyzer permits pings every 5s; this keeps a quiet watch
		// stream from being dropped by middleboxes.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	opts = append(opts, extraDialOptions...)
	conn, err := grpc.NewClient(f.addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("analyzer %s: %w", f.addr, err)
	}
	return conn, nil
}

// rpcError adds a hint for the errors an operator can act on.
func rpcError(rpc string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", rpc, err)
	}
	switch st.Code() {
	case codes.Unimplemented:
		return fmt.Errorf("%s: the analyzer does not implement this RPC (older release?): %s", rpc, st.Message())
	case codes.Unavailable:
		return fmt.Errorf("%s: analyzer unreachable: %s", rpc, st.Message())
	}
	return fmt.Errorf("%s: %s: %s", rpc, st.Code(), st.Message())
}

// compactJSON renders m as single-line protojson with deterministic spacing.
func compactJSON(m proto.Message) ([]byte, error) {
	b, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func indentJSON(m proto.Message) ([]byte, error) {
	b, err := compactJSON(m)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// usageError marks errors that should exit with status 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func exitCode(stderr io.Writer, cmd string, err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
	var ue usageError
	if errors.As(err, &ue) {
		return 2
	}
	return 1
}
