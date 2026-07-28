//go:build !linux

package internal

import "fmt"

type RawIPv4Sender struct{}

func NewRawIPv4Sender() (*RawIPv4Sender, error) {
	return nil, fmt.Errorf("raw IPv4 sender is supported only on Linux")
}

func (s *RawIPv4Sender) Close() error { return nil }
func (s *RawIPv4Sender) Send([]byte, uint32) error {
	return fmt.Errorf("raw IPv4 sender is supported only on Linux")
}
