package wrappers

import (
	"bytes"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/go-dpi/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func incrementalPacket(tb testing.TB, http bool, ordinal int) gopacket.Packet {
	tb.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{192, 0, 2, 1}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 49152, ACK: true, Seq: uint32(1 + ordinal*8), Window: 65535}
	payload := []byte{0x91, 0xe7, 0x42, 0x83, 0xb1, 0xc4, 0x9e, 0x72}
	if http {
		tcp.DstPort = 80
		payload = []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload)); err != nil {
		tb.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(ordinal)*1000000), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	return p
}

func TestIncrementalNativeState(t *testing.T) {
	for _, enabled := range []struct{ ndpi, lpi bool }{{true, false}, {false, true}, {true, true}} {
		worker, err := NewIncrementalWorker(enabled.ndpi, enabled.lpi)
		if err != nil {
			t.Fatal(err)
		}
		var flow IncrementalFlow
		for i := 0; i < 10; i++ {
			packet := incrementalPacket(t, false, i)
			if err := worker.Process(&flow, packet.Data()[14:], packet.Data(), uint64(packet.Metadata().Timestamp.UnixMilli()), 0, i == 9); err != nil {
				t.Fatal(err)
			}
		}
		if flow.ndpi != nil || flow.lpi != nil || !worker.Complete(&flow) {
			t.Fatal("exhausted state not freed")
		}
		worker.Free(&flow)
		worker.Free(&flow)
		worker.Close()
		worker.Close()
	}
}

func TestIncrementalDetectionAndOwnership(t *testing.T) {
	worker, err := NewIncrementalWorker(true, true)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	var flow IncrementalFlow
	packet := incrementalPacket(t, true, 0)
	if err := worker.Process(&flow, packet.Data()[14:], packet.Data(), 1700000000000, 0, false); err != nil {
		t.Fatal(err)
	}
	if flow.Count == 0 {
		t.Fatal("HTTP not detected")
	}
	if flow.ndpi != nil || flow.lpi != nil {
		t.Fatal("detected native state retained")
	}
	worker.Free(&flow)
	legacy := NewLPIWrapper()
	if legacy.InitializeWrapper() != 0 {
		t.Fatal("legacy LPI initialization failed")
	}
	legacy.DestroyWrapper()
	// Destroying a legacy wrapper must not invalidate another worker's shared library.
	flow = IncrementalFlow{}
	if err := worker.Process(&flow, packet.Data()[14:], packet.Data(), 1700000000000, 0, true); err != nil {
		t.Fatal(err)
	}
	if flow.Count == 0 {
		t.Fatal("legacy destroy invalidated incremental LPI")
	}
}

func TestIncrementalTruncatedAndFragmented(t *testing.T) {
	worker, err := NewIncrementalWorker(true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	packet := incrementalPacket(t, false, 0)
	for _, size := range []int{0, 1, 19, 20, 25} {
		var flow IncrementalFlow
		worker.Process(&flow, packet.Data()[14:14+size], nil, 0, 0, true)
		if flow.ndpi != nil {
			t.Fatal("truncated packet retained native state")
		}
	}
	ip := append([]byte(nil), packet.Data()[14:]...)
	ip[6] |= 0x20
	var flow IncrementalFlow
	if err := worker.Process(&flow, ip, nil, 0, 0, true); err == nil {
		t.Fatal("fragment accepted")
	}
}

func TestIncrementalCompactPromotion(t *testing.T) {
	worker, err := NewIncrementalWorker(true, false)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	var flow IncrementalFlow
	packet := incrementalPacket(t, false, 0)
	if err := worker.Process(&flow, packet.Data()[14:], nil, 1700000000000, 0, false); err != nil {
		t.Fatal(err)
	}
	if flow.ndpi != nil || !bytes.Equal(flow.firstIP, packet.Data()[14:]) {
		t.Fatal("single-packet flow did not use compact state")
	}
	packet.Data()[14] = 0xff
	if flow.firstIP[0] != 0x45 {
		t.Fatal("compact state borrowed the capture buffer")
	}
	packet = incrementalPacket(t, false, 1)
	if err := worker.Process(&flow, packet.Data()[14:], nil, 1700000000001, 0, false); err != nil {
		t.Fatal(err)
	}
	if flow.ndpi == nil || flow.firstIP != nil {
		t.Fatal("second packet did not promote to incremental state")
	}
	worker.Free(&flow)
}

// Benchmark fresh ten-packet flows, with one independent nDPI context per goroutine.
// DPI_BENCH_LEGACY=1 selects the original replay wrapper under its shared mutex.
func BenchmarkNativeIntegration(b *testing.B) {
	packets := make([]gopacket.Packet, 10)
	for i := range packets {
		packets[i] = incrementalPacket(b, false, i)
	}
	legacyMode := os.Getenv("DPI_BENCH_LEGACY") != ""
	var legacy *NDPIWrapper
	var workers []*IncrementalWorker
	if legacyMode {
		legacy = NewNDPIWrapper()
		if legacy.InitializeWrapper() != 0 {
			b.Fatal("nDPI initialization failed")
		}
		b.Cleanup(func() { legacy.DestroyWrapper() })
	} else {
		for i := 0; i < runtime.GOMAXPROCS(0); i++ {
			worker, err := NewIncrementalWorker(true, false)
			if err != nil {
				b.Fatal(err)
			}
			workers = append(workers, worker)
		}
		b.Cleanup(func() {
			for _, worker := range workers {
				worker.Close()
			}
		})
	}
	var next atomic.Uint64
	b.ReportAllocs()
	b.SetBytes(int64(len(packets[0].Data()) * 10))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var worker *IncrementalWorker
		if !legacyMode {
			worker = workers[next.Add(1)-1]
		}
		for pb.Next() {
			if legacyMode {
				flow := types.NewFlow()
				for _, packet := range packets {
					flow.AddPacket(packet)
					if _, err := legacy.ClassifyFlow(flow); err != nil {
						b.Error(err)
					}
				}
			} else {
				var flow IncrementalFlow
				for i, packet := range packets {
					if err := worker.Process(&flow, packet.Data()[14:], nil, uint64(packet.Metadata().Timestamp.UnixMilli()), 0, i == 9); err != nil {
						b.Error(err)
					}
				}
			}
		}
	})
	b.ReportMetric(10, "packets/op")
}
