package patterns

import (
	"testing"
	"time"
)

func jitteredGaps(base time.Duration, count int, jitterPercent int) []time.Duration {
	gaps := make([]time.Duration, count)
	for i := range gaps {
		offset := time.Duration(i%3-1) * base * time.Duration(jitterPercent) / 100
		gaps[i] = base + offset
	}
	return gaps
}

func TestIsMechanicalReuseTiming(t *testing.T) {
	tracker := &PatternTracker{}
	tests := []struct {
		name   string
		timing []time.Duration
		want   bool
	}{
		{"sub-millisecond gaps with low jitter", jitteredGaps(100*time.Microsecond, 20, 2), true},
		{"100ms gaps with low jitter", jitteredGaps(100*time.Millisecond, 20, 2), true},
		{"100ms gaps with high jitter", jitteredGaps(100*time.Millisecond, 20, 80), false},
		{"sub-millisecond gaps with high jitter", jitteredGaps(100*time.Microsecond, 20, 80), false},
		{"too few samples", jitteredGaps(100*time.Microsecond, 5, 2), false},
		{"zero gaps", make([]time.Duration, 20), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tracker.isMechanicalReuseTiming(tt.timing); got != tt.want {
				t.Fatalf("isMechanicalReuseTiming = %v, want %v", got, tt.want)
			}
		})
	}
}
