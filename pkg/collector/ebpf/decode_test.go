package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"testing"
)

func randomRecord(rng *rand.Rand, size int) []byte {
	record := make([]byte, size)
	for i := range record {
		record[i] = byte(rng.UintN(256))
	}
	return record
}

func TestDecodeEventMetadataMatchesBinaryRead(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 1000; i++ {
		record := randomRecord(rng, EventMetadataSize+rng.IntN(8))
		var want EventMetadata
		if err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &want); err != nil {
			t.Fatalf("binary.Read: %v", err)
		}
		got, err := DecodeEventMetadata(record)
		if err != nil {
			t.Fatalf("DecodeEventMetadata: %v", err)
		}
		if got != want {
			t.Fatalf("record %x: got %+v, want %+v", record, got, want)
		}
	}
}

func TestDecodeIncidentEventMatchesBinaryRead(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 1000; i++ {
		record := randomRecord(rng, IncidentEventSize+rng.IntN(8))
		var want IncidentEvent
		if err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &want); err != nil {
			t.Fatalf("binary.Read: %v", err)
		}
		got, err := DecodeIncidentEvent(record)
		if err != nil {
			t.Fatalf("DecodeIncidentEvent: %v", err)
		}
		if got != want {
			t.Fatalf("record %x: got %+v, want %+v", record, got, want)
		}
	}
}

func TestStructSizesFitCLayout(t *testing.T) {
	if size := binary.Size(EventMetadata{}); size > EventMetadataSize {
		t.Fatalf("EventMetadata wire size %d exceeds C size %d", size, EventMetadataSize)
	}
	if size := binary.Size(IncidentEvent{}); size != IncidentEventSize {
		t.Fatalf("IncidentEvent wire size %d, want %d", size, IncidentEventSize)
	}
}

func TestDecodeRejectsShortRecords(t *testing.T) {
	for size := 0; size < EventMetadataSize; size++ {
		if _, err := DecodeEventMetadata(make([]byte, size)); !errors.Is(err, ErrShortRecord) {
			t.Fatalf("event size %d: err = %v, want ErrShortRecord", size, err)
		}
	}
	for size := 0; size < IncidentEventSize; size++ {
		if _, err := DecodeIncidentEvent(make([]byte, size)); !errors.Is(err, ErrShortRecord) {
			t.Fatalf("incident size %d: err = %v, want ErrShortRecord", size, err)
		}
	}
}

func TestSourceAddrMatchesNetIP(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	for i := 0; i < 1000; i++ {
		record := randomRecord(rng, EventMetadataSize)
		record[48] = byte(i % 2)
		if i%4 == 3 {
			copy(record[0:12], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		}
		meta, err := DecodeEventMetadata(record)
		if err != nil {
			t.Fatalf("DecodeEventMetadata: %v", err)
		}
		var want net.IP
		if meta.IsV6 == 1 {
			want = net.IP(meta.SaddrV6[:])
		} else {
			want = make(net.IP, 4)
			binary.LittleEndian.PutUint32(want, meta.SaddrV4)
		}
		addr := meta.SourceAddr()
		if got := net.IP(addr.AsSlice()); !got.Equal(want) || len(got) != len(want) {
			t.Fatalf("SourceAddr bytes = %v, want %v", got, want)
		}
		if got := addr.Unmap().String(); got != want.String() {
			t.Fatalf("SourceAddr string = %q, want %q", got, want.String())
		}
	}
}
