package ml

import (
	"testing"
	"time"

	"PacketYeeter/pkg/analyzer/aidetection"
)

func TestSignalFeaturesKeepTCPMetadataThroughEventHistory(t *testing.T) {
	history := aidetection.NewEventHistory(10, time.Minute)
	history.AddEvent(aidetection.SignalEvent{
		Type:      aidetection.SignalSYNFlood,
		Source:    aidetection.SourceTCP,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"ttl":           uint32(64),
			"window_size":   uint32(65535),
			"entropy_score": uint32(50),
			"tcp_timestamp": uint32(123456),
		},
	})

	features := (&AdvancedFeatureExtractor{}).ExtractSignalFeatures(history.GetSnapshot())

	checks := []struct {
		idx  int
		want float32
		name string
	}{
		{15, 64, "ttl_avg"},
		{16, 1, "window_size_norm"},
		{17, 0.5, "entropy_score_norm"},
		{18, 1, "tcp_timestamp_ratio"},
	}
	for _, c := range checks {
		if features[c.idx] != c.want {
			t.Errorf("features[%d] (%s) = %v, want %v", c.idx, c.name, features[c.idx], c.want)
		}
	}
}
