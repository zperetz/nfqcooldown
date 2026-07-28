//go:build linux

package internal

import (
	"fmt"
	"sync"
	"syscall"
)

// RawIPv4Sender owns one IP_HDRINCL raw socket. Send is serialized because
// SO_MARK is a socket property and may differ between packets.
type RawIPv4Sender struct {
	fd int
	mu sync.Mutex
}

func NewRawIPv4Sender() (*RawIPv4Sender, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &RawIPv4Sender{fd: fd}, nil
}

func (s *RawIPv4Sender) Close() error {
	if s == nil || s.fd < 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return nil
	}
	err := syscall.Close(s.fd)
	s.fd = -1
	return err
}

func (s *RawIPv4Sender) Send(packet []byte, mark uint32) error {
	if s == nil {
		return fmt.Errorf("raw sender is not initialized")
	}
	if len(packet) < ipv4MinHeaderLen || packet[0]>>4 != 4 {
		return fmt.Errorf("not a complete IPv4 packet")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return fmt.Errorf("raw sender is closed")
	}
	if err := syscall.SetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
		return err
	}

	dst := &syscall.SockaddrInet4{}
	copy(dst.Addr[:], packet[16:20])
	return syscall.Sendto(s.fd, packet, 0, dst)
}
