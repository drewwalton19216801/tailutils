package tailutils

import (
	"fmt"
	"net"
)

// Network is an interface that abstracts the network operations used in tailutils.
type Network interface {
	ParseCIDR(s string) (*net.IP, *net.IPNet, error)
	Interfaces() ([]net.Interface, error)
	Addrs(iface net.Interface) ([]net.Addr, error)
}

// RealNetwork is the real implementation of the Network interface using the net package.
type RealNetwork struct{}

func (rn *RealNetwork) ParseCIDR(s string) (*net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	return &ip, ipNet, err
}

func (rn *RealNetwork) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func (rn *RealNetwork) Addrs(iface net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

// DefaultNetwork is the default implementation used in production.
var DefaultNetwork Network = &RealNetwork{}

// GetTailscaleIP returns the IP address of the tailscale interface.
func GetTailscaleIP() (string, error) {
	return getTailscaleIP(DefaultNetwork)
}

func getTailscaleIP(netImpl Network) (string, error) {
	// Define the Tailscale IP range
	_, tsNet, err := netImpl.ParseCIDR("100.64.0.0/10")
	if err != nil {
		return "", fmt.Errorf("failed to parse Tailscale IP range: %v", err)
	}

	// Get the list of network interfaces
	ifaces, err := netImpl.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Find the Tailscale interface
	for _, iface := range ifaces {
		// Skip interfaces that are down or are loopback interfaces
		if (iface.Flags&net.FlagUp == 0) || (iface.Flags&net.FlagLoopback != 0) {
			continue
		}

		// Get all addresses associated with the interface
		addrs, err := netImpl.Addrs(iface)
		if err != nil {
			return "", fmt.Errorf("failed to get interface addresses: %v", err)
		}

		// Check if any of the addresses belong to the Tailscale IP range
		for _, addr := range addrs {
			// Check if the address is an IPNet
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Consider only IPv4 addresses
			if ipNet.IP.To4() == nil {
				continue
			}

			// Check if the address is within the Tailscale network
			if tsNet.Contains(ipNet.IP) {
				return ipNet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("tailscale interface not found")
}

// HasTailscaleIP returns true if the machine has a Tailscale interface.
func HasTailscaleIP() (bool, error) {
	return hasTailscaleIP(DefaultNetwork)
}

func hasTailscaleIP(netImpl Network) (bool, error) {
	_, err := getTailscaleIP(netImpl)
	if err != nil {
		return false, err
	}
	return true, nil
}
