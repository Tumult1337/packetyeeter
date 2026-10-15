package collector

import (
	"testing"
	"time"

	apiv1 "PacketYeeter/api/proto/v1"
)

func clientKey(client int) uint32 {
	return uint32(client) << 8
}

type egressEntry struct {
	key   uint32
	total uint64
}

func walkEntries(entries []egressEntry) func(func(uint32, uint64) bool) error {
	return func(visit func(uint32, uint64) bool) error {
		for _, entry := range entries {
			if !visit(entry.key, entry.total) {
				return nil
			}
		}
		return nil
	}
}

func drainWeights(queue chan *apiv1.Signal) map[string]float64 {
	weights := map[string]float64{}
	for {
		select {
		case signal := <-queue:
			weights[string(signal.Ip)] = signal.Weight
		default:
			return weights
		}
	}
}

func TestEgressRateOfClientPastBatchCapIsPerInterval(t *testing.T) {
	const (
		clientCount  = egressMaxBatchSize + 1
		bytesPerPoll = 10_000
		interval     = time.Second
	)
	c := &Collector{
		Config:      Config{EgressMinBytes: 1, PollInterval: interval},
		signalQueue: make(chan *apiv1.Signal, 4*clientCount),
	}
	prev := map[uint32]prevEgress{}
	start := time.Unix(1_700_000_000, 0)
	var lastPoll time.Time

	entriesForPoll := func(poll int) []egressEntry {
		entries := make([]egressEntry, 0, clientCount)
		for client := 1; client <= clientCount; client++ {
			entries = append(entries, egressEntry{key: clientKey(client), total: uint64(poll * bytesPerPoll)})
		}
		if poll == 3 {
			last := entries[len(entries)-1]
			entries = append([]egressEntry{last}, entries[:len(entries)-1]...)
		}
		return entries
	}

	var weights map[string]float64
	for poll := 1; poll <= 3; poll++ {
		now := start.Add(time.Duration(poll) * interval)
		window := egressWindowSeconds(lastPoll, now, interval)
		lastPoll = now
		if _, _, err := pollEgressMap(c, prev, walkEntries(entriesForPoll(poll)), ipv4FromKey, now, window); err != nil {
			t.Fatalf("poll %d: %v", poll, err)
		}
		weights = drainWeights(c.signalQueue)
	}

	pastCap := string(ipv4FromKey(clientKey(clientCount)))
	got, ok := weights[pastCap]
	if !ok {
		t.Fatal("client past the batch cap was not reported on poll 3")
	}
	want := float64(bytesPerPoll) / interval.Seconds()
	if got != want {
		t.Fatalf("rate of client past the cap = %v bytes/s, want %v", got, want)
	}
	if len(weights) != egressMaxBatchSize {
		t.Fatalf("poll 3 reported %d clients, want %d", len(weights), egressMaxBatchSize)
	}
}

func TestEgressWindowSeconds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name       string
		lastPoll   time.Time
		now        time.Time
		configured time.Duration
		want       float64
	}{
		{"first poll uses configured interval", time.Time{}, now, 5 * time.Second, 5},
		{"first poll defaults to one second", time.Time{}, now, 0, 1},
		{"slow poll uses measured time", now, now.Add(3 * time.Second), time.Second, 3},
		{"fast poll uses measured time", now, now.Add(500 * time.Millisecond), time.Second, 0.5},
		{"same instant is bounded below", now, now, time.Second, egressMinWindow.Seconds()},
		{"clock step back is bounded below", now, now.Add(-time.Second), time.Second, egressMinWindow.Seconds()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := egressWindowSeconds(tt.lastPoll, tt.now, tt.configured); got != tt.want {
				t.Fatalf("egressWindowSeconds = %v, want %v", got, tt.want)
			}
		})
	}
}
