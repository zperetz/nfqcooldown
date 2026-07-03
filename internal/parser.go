package internal

import "net"

func ParseIPv4PureTCPSYN(data []byte) (string, bool) {
	if len(data) < 40 || data[0]>>4 != 4 { return "", false }
	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl+20 || data[9] != 6 { return "", false }
	srcIP := net.IPv4(data[12], data[13], data[14], data[15]).String()
	tcp := data[ihl:]
	flags := tcp[13]
	syn := flags&0x02 != 0
	ack := flags&0x10 != 0
	rst := flags&0x04 != 0
	fin := flags&0x01 != 0
	return srcIP, syn && !ack && !rst && !fin
}
