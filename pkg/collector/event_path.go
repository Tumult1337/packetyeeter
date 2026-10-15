package collector

import (
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"PacketYeeter/pkg/collector/ebpf"
	"PacketYeeter/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

const (
	incidentSummaryInterval = 10 * time.Second
	incidentReasonSlots     = ebpf.IncidentRuleMatch + 1
	unknownIncidentSlot     = 0
)

type incidentLog struct {
	counts   [incidentReasonSlots]atomic.Uint64
	counters [incidentReasonSlots]prometheus.Counter
}

func incidentReasonSlot(reason uint8) uint8 {
	if reason >= incidentReasonSlots {
		return unknownIncidentSlot
	}
	return reason
}

func (l *incidentLog) counter(slot uint8) prometheus.Counter {
	if l.counters[slot] == nil {
		l.counters[slot] = metrics.KernelIncidents.WithLabelValues(ebpf.IncidentReasonName(slot))
	}
	return l.counters[slot]
}

func (l *incidentLog) firstInInterval(slot uint8) bool {
	return l.counts[slot].Add(1) == 1
}

func (c *Collector) reportIncidentSummaries() {
	defer c.wg.Done()
	ticker := time.NewTicker(incidentSummaryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			c.logIncidentSummaries()
			return
		case <-ticker.C:
			c.logIncidentSummaries()
		}
	}
}

func (c *Collector) logIncidentSummaries() {
	for slot := range c.incidentLog.counts {
		count := c.incidentLog.counts[slot].Swap(0)
		if count <= 1 {
			continue
		}
		c.Logger.WithFields(logrus.Fields{
			"reason":   ebpf.IncidentReasonName(uint8(slot)),
			"count":    count,
			"interval": incidentSummaryInterval,
		}).Warn("Kernel-space enforcement incident summary")
	}
}

func tcpMetaSignalID(addr netip.Addr, seq uint32) string {
	var buf [64]byte
	id := append(buf[:0], "tcp-meta-"...)
	id = addr.Unmap().AppendTo(id)
	id = append(id, '-')
	id = strconv.AppendUint(id, uint64(seq), 10)
	return string(id)
}
