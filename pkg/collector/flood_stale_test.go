package collector

import (
	"testing"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
)

const testPollInterval = time.Second

func TestFloodPPSStaleEntryNoSignal(t *testing.T) {
	prev := map[uint32]prevRate{}
	const ip = uint32(7)
	firstPoll := uint64(100 * time.Second)
	rate := ebpf.ICMPRate{LastTime: firstPoll - uint64(10*time.Second), Count: 5000}

	for poll, nowNS := range []uint64{firstPoll, firstPoll + uint64(testPollInterval)} {
		if pps, flood := floodPPS(prev, ip, rate, newRateFreshness(nowNS, testPollInterval)); flood {
			t.Fatalf("poll %d: stale entry signalled at %v pps", poll, pps)
		}
	}
	if _, kept := prev[ip]; kept {
		t.Fatal("stale entry left a previous-window sample")
	}
}

func TestFloodPPSStaleEntryNoSignalV6(t *testing.T) {
	prev := map[[16]byte]prevRate{}
	var key [16]byte
	key[0] = 0x20
	nowNS := uint64(100 * time.Second)
	rate := ebpf.ICMPRate{LastTime: nowNS - uint64(10*time.Second), Count: 5000}

	if pps, flood := floodPPS(prev, key, rate, newRateFreshness(nowNS, testPollInterval)); flood {
		t.Fatalf("stale IPv6 entry signalled at %v pps", pps)
	}
}

func TestFloodPPSFreshEntrySignals(t *testing.T) {
	nowNS := uint64(100 * time.Second)
	cases := []struct {
		name     string
		lastTime uint64
	}{
		{"window started now", nowNS},
		{"window open half a second", nowNS - uint64(500*time.Millisecond)},
		{"at the stale bound", nowNS - uint64(bpfRateWindow+testPollInterval)},
		{"written after the clock read", nowNS + uint64(time.Millisecond)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := map[uint32]prevRate{}
			rate := ebpf.ICMPRate{LastTime: tc.lastTime, Count: 5000}
			pps, flood := floodPPS(prev, uint32(7), rate, newRateFreshness(nowNS, testPollInterval))
			if !flood || pps != 5000 {
				t.Fatalf("floodPPS = %v, %v; want 5000, true", pps, flood)
			}
		})
	}
}

func TestFloodPPSUnknownClockKeepsSignal(t *testing.T) {
	prev := map[uint32]prevRate{}
	rate := ebpf.ICMPRate{LastTime: 1, Count: 5000}

	pps, flood := floodPPS(prev, uint32(7), rate, rateFreshness{})
	if !flood || pps != 5000 {
		t.Fatalf("floodPPS = %v, %v; want 5000, true", pps, flood)
	}
}

func TestFloodPPSBelowThresholdNoSignal(t *testing.T) {
	nowNS := uint64(100 * time.Second)
	prev := map[uint32]prevRate{}
	rate := ebpf.ICMPRate{LastTime: nowNS, Count: 3}

	if _, flood := floodPPS(prev, uint32(7), rate, newRateFreshness(nowNS, testPollInterval)); flood {
		t.Fatal("sub-threshold entry signalled")
	}
}
