package collector

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

func TestTCPMetaSignalIDMatchesSprintf(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("::ffff:198.51.100.7"),
		netip.MustParseAddr("2001:db8:0:1:1:1:1:1"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	}
	for _, addr := range addrs {
		for _, seq := range []uint32{0, 1, 4294967295} {
			want := fmt.Sprintf("tcp-meta-%s-%d", net.IP(addr.AsSlice()).String(), seq)
			if got := tcpMetaSignalID(addr, seq); got != want {
				t.Errorf("tcpMetaSignalID(%s, %d) = %q, want %q", addr, seq, got, want)
			}
		}
	}
}

func TestSynCacheMatchesMappedAndPlainForms(t *testing.T) {
	c := &Collector{}
	c.storeSynTimestamp(netip.MustParseAddr("::ffff:192.0.2.9"))
	if _, ok := c.getSynTimestamp(net.ParseIP("192.0.2.9")); !ok {
		t.Fatal("16-byte lookup missed an entry stored from a mapped address")
	}
	c.storeSynTimestamp(netip.MustParseAddr("192.0.2.10"))
	if _, ok := c.getSynTimestamp(net.ParseIP("192.0.2.10").To4()); !ok {
		t.Fatal("4-byte lookup missed an entry stored from an IPv4 address")
	}
	if _, ok := c.getSynTimestamp(net.ParseIP("192.0.2.10")); ok {
		t.Fatal("getSynTimestamp returned an entry that was already removed")
	}
	if _, ok := c.getSynTimestamp(nil); ok {
		t.Fatal("getSynTimestamp found an entry for a nil IP")
	}
}

func synRecord(addr netip.Addr) []byte {
	record := make([]byte, ebpf.EventMetadataSize)
	if addr.Is4() {
		v4 := addr.As4()
		copy(record[16:20], v4[:])
	} else {
		v6 := addr.As16()
		copy(record[0:16], v6[:])
		record[48] = 1
	}
	record[47] = 1
	record[50] = 0x02
	return record
}

func TestProcessPerfEventSynCacheFollowsMode(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	addr := netip.MustParseAddr("192.0.2.20")

	host, err := New(Config{}, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	host.processPerfEvent(synRecord(addr))
	if _, ok := host.getSynTimestamp(net.IP(addr.AsSlice())); !ok {
		t.Fatal("host mode did not store the SYN timestamp")
	}

	scrub, err := New(Config{Mode: ebpf.ModeScrub, Interface: "eth0", InsideInterface: "eth1", XDPMode: ebpf.XDPModeAuto}, logger)
	if err != nil {
		t.Fatalf("New scrub: %v", err)
	}
	scrub.processPerfEvent(synRecord(addr))
	if _, ok := scrub.getSynTimestamp(net.IP(addr.AsSlice())); ok {
		t.Fatal("scrub mode stored a SYN timestamp without a SPOE consumer")
	}
}

func TestProcessPerfEventCountsShortRecord(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	c := &Collector{Logger: logger}

	before := testutil.ToFloat64(metrics.PerfShortRecords.WithLabelValues("tcp_metadata"))
	c.processPerfEvent(make([]byte, ebpf.EventMetadataSize-1))
	after := testutil.ToFloat64(metrics.PerfShortRecords.WithLabelValues("tcp_metadata"))
	if got := after - before; got != 1 {
		t.Fatalf("short-record metric increment = %v, want 1", got)
	}
}

func incidentRecord(addr netip.Addr, reason uint8) []byte {
	record := make([]byte, ebpf.IncidentEventSize)
	if addr.Is4() {
		v4 := addr.As4()
		copy(record[8:12], v4[:])
	} else {
		v6 := addr.As16()
		copy(record[12:28], v6[:])
		record[28] = 1
	}
	record[29] = reason
	return record
}

func TestProcessIncidentEventLogsFirstAndSummary(t *testing.T) {
	var logs bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logs)
	logger.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	c := &Collector{Logger: logger}

	counter := metrics.KernelIncidents.WithLabelValues("udp_rate")
	before := testutil.ToFloat64(counter)
	for i := 0; i < 5; i++ {
		c.processIncidentEvent(incidentRecord(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), ebpf.IncidentUDPRate))
	}
	c.processIncidentEvent(incidentRecord(netip.MustParseAddr("2001:db8::5"), ebpf.IncidentBlockedIP))
	if got := testutil.ToFloat64(counter) - before; got != 5 {
		t.Fatalf("udp_rate counter increment = %v, want 5", got)
	}

	firstLines := strings.Count(logs.String(), `msg="Kernel-space enforcement incident"`)
	if firstLines != 2 {
		t.Fatalf("first-occurrence lines = %d, want 2:\n%s", firstLines, logs.String())
	}
	if !strings.Contains(logs.String(), "ip=192.0.2.0") || !strings.Contains(logs.String(), "ip=\"2001:db8::5\"") {
		t.Fatalf("first-occurrence lines miss the source address:\n%s", logs.String())
	}

	logs.Reset()
	c.logIncidentSummaries()
	if !strings.Contains(logs.String(), "count=5") || !strings.Contains(logs.String(), "reason=udp_rate") {
		t.Fatalf("summary line missing udp_rate count:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "reason=blocked_ip") {
		t.Fatalf("summary repeated a single incident that already has a first-occurrence line:\n%s", logs.String())
	}

	logs.Reset()
	c.processIncidentEvent(incidentRecord(netip.MustParseAddr("192.0.2.200"), ebpf.IncidentUDPRate))
	if !strings.Contains(logs.String(), "ip=192.0.2.200") {
		t.Fatalf("new interval did not log a first occurrence:\n%s", logs.String())
	}
}

func TestIncidentReasonSlotMapsUnknownCodes(t *testing.T) {
	for _, reason := range []uint8{0, ebpf.IncidentRuleMatch + 1, 255} {
		if got := ebpf.IncidentReasonName(incidentReasonSlot(reason)); got != ebpf.IncidentReasonName(reason) {
			t.Errorf("reason %d: slot name %q, want %q", reason, got, ebpf.IncidentReasonName(reason))
		}
	}
	for reason := uint8(ebpf.IncidentBlockedIP); reason <= ebpf.IncidentRuleMatch; reason++ {
		if got := incidentReasonSlot(reason); got != reason {
			t.Errorf("reason %d: slot %d", reason, got)
		}
	}
}
