package collector

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
)

const (
	benchRecordPool    = 4096
	benchPerfRecordLen = 56
	benchIncidentLen   = 32
	benchIncidentKinds = 8
)

func benchCollector(b *testing.B) *Collector {
	b.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.WarnLevel)
	c, err := New(Config{}, logger)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return c
}

func benchSourceV4(i int) [4]byte {
	return [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
}

func benchSynRecords() [][]byte {
	records := make([][]byte, benchRecordPool)
	for i := range records {
		record := make([]byte, benchPerfRecordLen)
		v4 := benchSourceV4(i)
		copy(record[16:20], v4[:])
		binary.LittleEndian.PutUint32(record[24:28], uint32(i))
		binary.LittleEndian.PutUint32(record[28:32], uint32(i)*7)
		binary.LittleEndian.PutUint16(record[36:38], uint16(40000+i))
		binary.LittleEndian.PutUint16(record[38:40], 443)
		binary.LittleEndian.PutUint16(record[40:42], 64240)
		binary.LittleEndian.PutUint16(record[44:46], 1460)
		record[46] = 6
		record[47] = 1
		record[49] = 64
		record[50] = 0x02
		record[52] = 1
		record[53] = 42
		records[i] = record
	}
	return records
}

func benchIncidentRecords() [][]byte {
	records := make([][]byte, benchRecordPool)
	for i := range records {
		record := make([]byte, benchIncidentLen)
		binary.LittleEndian.PutUint64(record[0:8], uint64(i)*1000)
		v4 := benchSourceV4(i)
		copy(record[8:12], v4[:])
		record[29] = byte(i%benchIncidentKinds) + 1
		records[i] = record
	}
	return records
}

func BenchmarkProcessPerfEvent(b *testing.B) {
	c := benchCollector(b)
	records := benchSynRecords()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.processPerfEvent(records[i%benchRecordPool])
	}
}

func BenchmarkProcessIncidentEvent(b *testing.B) {
	c := benchCollector(b)
	records := benchIncidentRecords()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.processIncidentEvent(records[i%benchRecordPool])
	}
}

func BenchmarkControlUntouched(b *testing.B) {
	c := benchCollector(b)
	sources := make([]net.IP, benchRecordPool)
	for i := range sources {
		v4 := benchSourceV4(i)
		sources[i] = net.IP(v4[:])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.emitEgressSignal(sources[i%benchRecordPool], 1<<20, uint64(i), 10)
	}
}
