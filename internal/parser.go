package internal

import (
	"encoding/binary"
	"net"
)

func ParseIPv4PureTCPSYN(data []byte) (string, bool) {
	if len(data) < 40 || data[0]>>4 != 4 {
		return "", false
	}
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+20 || data[9] != 6 {
		return "", false
	}
	srcIP := net.IPv4(data[12], data[13], data[14], data[15]).String()
	tcp := data[ihl:]
	flags := tcp[13]
	syn := flags&0x02 != 0
	ack := flags&0x10 != 0
	rst := flags&0x04 != 0
	fin := flags&0x01 != 0
	return srcIP, syn && !ack && !rst && !fin
}

type PacketInfo struct {
	ClientIP   string
	ClientPort uint16
	ServerPort uint16
	Seq        uint32
	Ack        uint32
}

func ParseIPv4TCPSYNACK(data []byte) (PacketInfo, bool) {
	var info PacketInfo

	if len(data) < 40 || data[0]>>4 != 4 {
		return info, false
	}

	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+20 || data[9] != 6 {
		return info, false
	}

	tcp := data[ihl:]
	flags := tcp[13]

	syn := flags&0x02 != 0
	ack := flags&0x10 != 0
	rst := flags&0x04 != 0
	fin := flags&0x01 != 0

	if !(syn && ack && !rst && !fin) {
		return info, false
	}

	// Для исходящего SYN/ACK клиент — это destination IP,
	// destination port — порт клиента, source port — порт сервера.
	info.ClientIP = net.IPv4(data[16], data[17], data[18], data[19]).String()
	info.ServerPort = binary.BigEndian.Uint16(tcp[0:2])
	info.ClientPort = binary.BigEndian.Uint16(tcp[2:4])
	info.Seq = binary.BigEndian.Uint32(tcp[4:8])
	info.Ack = binary.BigEndian.Uint32(tcp[8:12])

	return info, true
}
