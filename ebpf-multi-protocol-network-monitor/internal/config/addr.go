package config

import (
	"fmt"
	"net"
	"strconv"
)

// PortFromAddr extracts the TCP/UDP port from a host:port address.
func PortFromAddr(addr string) (uint, error) {
	if addr == "" {
		return 0, fmt.Errorf("address is empty")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port == 0 {
		return 0, fmt.Errorf("port must be > 0")
	}
	return uint(port), nil
}
