package tailutils

import (
	"fmt"
	"net"
)

var (
	TailscaleIP4CIDR = "100.64.0.0/10"
	TailscaleIP6CIDR = "fd7a:115c:a1e0::/48"
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
	_, tsNet, err := netImpl.ParseCIDR(TailscaleIP4CIDR)
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

// HasTailscaleIP returns true if the machine has a Tailscale interface (either IPv4 or IPv6).
func HasTailscaleIP() (bool, error) {
	// Check if the machine has a Tailscale IPv4 interface
	hasIPv4, err := hasTailscaleIP(DefaultNetwork)
	if err != nil {
		return false, err
	}

	// Check if the machine has a Tailscale IPv6 interface
	hasIPv6, err := hasTailscaleIP6(DefaultNetwork)
	if err != nil {
		return false, err
	}

	return hasIPv4 || hasIPv6, nil
}

func hasTailscaleIP(netImpl Network) (bool, error) {
	_, err := getTailscaleIP(netImpl)
	if err != nil {
		return false, err
	}
	return true, nil
}

func hasTailscaleIP6(netImpl Network) (bool, error) {
	_, err := getTailscaleIP6(netImpl)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetTailscaleIP6 returns the IPv6 address of the Tailscale interface.
func GetTailscaleIP6() (string, error) {
	return getTailscaleIP6(DefaultNetwork)
}

func getTailscaleIP6(netImpl Network) (string, error) {
	// Define the Tailscale IPv6 range
	_, tsNet, err := netImpl.ParseCIDR(TailscaleIP6CIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse Tailscale IPv6 range: %v", err)
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

		// Check if any of the addresses belong to the Tailscale IPv6 range
		for _, addr := range addrs {
			// Check if the address is an IPNet
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Consider only IPv6 addresses
			if ipNet.IP.To4() != nil {
				continue
			}

			// Check if the address is within the Tailscale IPv6 network
			if tsNet.Contains(ipNet.IP) {
				return ipNet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("tailscale IPv6 interface not found")
}
