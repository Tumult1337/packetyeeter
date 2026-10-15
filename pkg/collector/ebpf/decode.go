package ebpf

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	EventMetadataSize = 56
	IncidentEventSize = 32
)

var ErrShortRecord = errors.New("perf record shorter than its struct")

func DecodeEventMetadata(data []byte) (EventMetadata, error) {
	if len(data) < EventMetadataSize {
		return EventMetadata{}, ErrShortRecord
	}
	le := binary.LittleEndian
	var meta EventMetadata
	copy(meta.SaddrV6[:], data[0:16])
	meta.SaddrV4 = le.Uint32(data[16:20])
	meta.RttUs = le.Uint32(data[20:24])
	meta.Seq = le.Uint32(data[24:28])
	meta.TsVal = le.Uint32(data[28:32])
	meta.TsEcr = le.Uint32(data[32:36])
	meta.Sport = le.Uint16(data[36:38])
	meta.Dport = le.Uint16(data[38:40])
	meta.Window = le.Uint16(data[40:42])
	meta.Len = le.Uint16(data[42:44])
	meta.Mss = le.Uint16(data[44:46])
	meta.Protocol = data[46]
	meta.Type = data[47]
	meta.IsV6 = data[48]
	meta.TTL = data[49]
	meta.TcpFlags = data[50]
	meta.Ipv6ExtHeaders = data[51]
	meta.HasTimestamp = data[52]
	meta.EntropyScore = data[53]
	return meta, nil
}

func DecodeIncidentEvent(data []byte) (IncidentEvent, error) {
	if len(data) < IncidentEventSize {
		return IncidentEvent{}, ErrShortRecord
	}
	le := binary.LittleEndian
	var inc IncidentEvent
	inc.Timestamp = le.Uint64(data[0:8])
	inc.SaddrV4 = le.Uint32(data[8:12])
	copy(inc.SaddrV6[:], data[12:28])
	inc.IsV6 = data[28]
	inc.Reason = data[29]
	return inc, nil
}

func (m *EventMetadata) SourceAddr() netip.Addr {
	return sourceAddr(m.IsV6, m.SaddrV4, m.SaddrV6)
}

func (e *IncidentEvent) SourceAddr() netip.Addr {
	return sourceAddr(e.IsV6, e.SaddrV4, e.SaddrV6)
}

func sourceAddr(isV6 uint8, saddrV4 uint32, saddrV6 [16]byte) netip.Addr {
	if isV6 == 1 {
		return netip.AddrFrom16(saddrV6)
	}
	var v4 [4]byte
	binary.LittleEndian.PutUint32(v4[:], saddrV4)
	return netip.AddrFrom4(v4)
}
