package internal

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ipv4MinHeaderLen = 20
	tcpMinHeaderLen  = 20
	ipProtoTCP       = 6
)

// TCPPayloadInfo describes an IPv4/TCP packet containing application payload.
type TCPPayloadInfo struct {
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Seq           uint32
	Ack           uint32
	Flags         uint8
	IPHeaderLen   int
	TCPHeaderLen  int
	PayloadOffset int
	PayloadLen    int
	TotalLen      int
}

// ParseIPv4TCPPayload accepts a complete IPv4 packet copied by NFQUEUE.
// It rejects fragments because splitting a fragmented TCP packet is unsafe.
func ParseIPv4TCPPayload(packet []byte) (TCPPayloadInfo, bool) {
	if len(packet) < ipv4MinHeaderLen+tcpMinHeaderLen || packet[0]>>4 != 4 {
		return TCPPayloadInfo{}, false
	}

	ipHeaderLen := int(packet[0]&0x0f) * 4
	if ipHeaderLen < ipv4MinHeaderLen || len(packet) < ipHeaderLen+tcpMinHeaderLen {
		return TCPPayloadInfo{}, false
	}
	if packet[9] != ipProtoTCP {
		return TCPPayloadInfo{}, false
	}

	// MF or a non-zero fragment offset means the packet is fragmented.
	frag := binary.BigEndian.Uint16(packet[6:8])
	if frag&0x3fff != 0 {
		return TCPPayloadInfo{}, false
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ipHeaderLen+tcpMinHeaderLen || totalLen > len(packet) {
		return TCPPayloadInfo{}, false
	}

	tcp := packet[ipHeaderLen:totalLen]
	tcpHeaderLen := int(tcp[12]>>4) * 4
	if tcpHeaderLen < tcpMinHeaderLen || len(tcp) < tcpHeaderLen {
		return TCPPayloadInfo{}, false
	}

	payloadOffset := ipHeaderLen + tcpHeaderLen
	payloadLen := totalLen - payloadOffset
	if payloadLen <= 0 {
		return TCPPayloadInfo{}, false
	}

	return TCPPayloadInfo{
		SrcIP:         net.IPv4(packet[12], packet[13], packet[14], packet[15]),
		DstIP:         net.IPv4(packet[16], packet[17], packet[18], packet[19]),
		SrcPort:       binary.BigEndian.Uint16(tcp[0:2]),
		DstPort:       binary.BigEndian.Uint16(tcp[2:4]),
		Seq:           binary.BigEndian.Uint32(tcp[4:8]),
		Ack:           binary.BigEndian.Uint32(tcp[8:12]),
		Flags:         tcp[13],
		IPHeaderLen:   ipHeaderLen,
		TCPHeaderLen:  tcpHeaderLen,
		PayloadOffset: payloadOffset,
		PayloadLen:    payloadLen,
		TotalLen:      totalLen,
	}, true
}

// SplitIPv4TCPPacket replaces one TCP segment with two segments covering the
// same sequence-space interval and carrying exactly the same payload bytes.
func SplitIPv4TCPPacket(packet []byte, info TCPPayloadInfo, splitAt int) ([]byte, []byte, error) {
	if splitAt <= 0 || splitAt >= info.PayloadLen {
		return nil, nil, fmt.Errorf("split offset %d is outside payload length %d", splitAt, info.PayloadLen)
	}
	if info.TotalLen > len(packet) || info.PayloadOffset < 0 || info.PayloadOffset > info.TotalLen {
		return nil, nil, fmt.Errorf("invalid packet metadata")
	}

	header := packet[:info.PayloadOffset]
	payload := packet[info.PayloadOffset:info.TotalLen]

	first := make([]byte, len(header)+splitAt)
	copy(first, header)
	copy(first[len(header):], payload[:splitAt])

	secondPayload := payload[splitAt:]
	second := make([]byte, len(header)+len(secondPayload))
	copy(second, header)
	copy(second[len(header):], secondPayload)

	firstTCP := first[info.IPHeaderLen:]
	secondTCP := second[info.IPHeaderLen:]

	// PSH and FIN belong on the final segment. ACK and all TCP options remain.
	firstTCP[13] &^= 0x09
	binary.BigEndian.PutUint32(secondTCP[4:8], info.Seq+uint32(splitAt))

	fixIPv4TCPChecksums(first, info.IPHeaderLen)
	fixIPv4TCPChecksums(second, info.IPHeaderLen)
	return first, second, nil
}

func fixIPv4TCPChecksums(packet []byte, ipHeaderLen int) {
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:ipHeaderLen]))

	tcp := packet[ipHeaderLen:]
	tcp[16], tcp[17] = 0, 0

	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], internetChecksum(pseudo))
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
