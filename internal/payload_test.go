package internal

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeTestPacket(payload []byte, flags byte) []byte {
	packet := make([]byte, 20+20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = ipProtoTCP
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{198, 51, 100, 20})

	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 50123)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	binary.BigEndian.PutUint32(tcp[8:12], 5000)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)

	fixIPv4TCPChecksums(packet, 20)
	return packet
}

func TestParseIPv4TCPPayload(t *testing.T) {
	packet := makeTestPacket([]byte("abcdef"), 0x18)
	info, ok := ParseIPv4TCPPayload(packet)
	if !ok {
		t.Fatal("packet was not parsed")
	}
	if info.SrcPort != 443 || info.DstPort != 50123 || info.Seq != 1000 || info.PayloadLen != 6 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestSplitIPv4TCPPacket(t *testing.T) {
	originalPayload := []byte("abcdef")
	packet := makeTestPacket(originalPayload, 0x19) // ACK|PSH|FIN
	info, ok := ParseIPv4TCPPayload(packet)
	if !ok {
		t.Fatal("packet was not parsed")
	}

	first, second, err := SplitIPv4TCPPacket(packet, info, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstInfo, ok := ParseIPv4TCPPayload(first)
	if !ok {
		t.Fatal("first segment was not parsed")
	}
	secondInfo, ok := ParseIPv4TCPPayload(second)
	if !ok {
		t.Fatal("second segment was not parsed")
	}

	if firstInfo.Seq != 1000 || secondInfo.Seq != 1001 {
		t.Fatalf("unexpected sequence numbers: %d, %d", firstInfo.Seq, secondInfo.Seq)
	}
	if firstInfo.Flags&0x09 != 0 {
		t.Fatalf("first segment retained PSH/FIN: flags=0x%x", firstInfo.Flags)
	}
	if secondInfo.Flags != 0x19 {
		t.Fatalf("second segment flags changed: 0x%x", secondInfo.Flags)
	}

	reassembled := append([]byte{}, first[firstInfo.PayloadOffset:firstInfo.TotalLen]...)
	reassembled = append(reassembled, second[secondInfo.PayloadOffset:secondInfo.TotalLen]...)
	if !bytes.Equal(reassembled, originalPayload) {
		t.Fatalf("payload changed: got %q", reassembled)
	}
	if internetChecksum(first[:firstInfo.IPHeaderLen]) != 0 {
		t.Fatal("first IPv4 checksum is invalid")
	}
	if internetChecksum(second[:secondInfo.IPHeaderLen]) != 0 {
		t.Fatal("second IPv4 checksum is invalid")
	}
}

func TestSplitRejectsInvalidOffset(t *testing.T) {
	packet := makeTestPacket([]byte("a"), 0x18)
	info, _ := ParseIPv4TCPPayload(packet)
	if _, _, err := SplitIPv4TCPPacket(packet, info, 1); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseRejectsFragment(t *testing.T) {
	packet := makeTestPacket([]byte("abc"), 0x18)
	binary.BigEndian.PutUint16(packet[6:8], 0x2000)
	if _, ok := ParseIPv4TCPPayload(packet); ok {
		t.Fatal("fragmented packet was accepted")
	}
}
