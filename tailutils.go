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
	ParseIP(s string) (*net.IP, error)
	Interfaces() ([]net.Interface, error)
	Addrs(iface net.Interface) ([]net.Addr, error)
}

// RealNetwork is the real implementation of the Network interface using the net package.
type RealNetwork struct{}

func (rn *RealNetwork) ParseCIDR(s string) (*net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	return &ip, ipNet, err
}

func (rn *RealNetwork) ParseIP(s string) (*net.IP, error) {
	ip := net.ParseIP(s)
	return &ip, nil
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

// GetInterfaceName returns the name of the network interface for the given IP address
func GetInterfaceName(ip string) (string, error) {
	return getInterfaceName(DefaultNetwork, ip)
}

// getInterfaceName returns the name of the network interface for the given IP address, but
// only for Tailscale IP ranges.
func getInterfaceName(netImpl Network, ip string) (string, error) {
	// Ensure the IP address given is within the Tailscale IPv4 or IPv6 range
	_, tsNet, err := netImpl.ParseCIDR(TailscaleIP4CIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse Tailscale IP range: %v", err)
	}
	_, tsNet6, err := netImpl.ParseCIDR(TailscaleIP6CIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse Tailscale IPv6 range: %v", err)
	}
	if !tsNet.Contains(net.ParseIP(ip)) && !tsNet6.Contains(net.ParseIP(ip)) {
		return "", fmt.Errorf("IP address %s is not within the Tailscale IP range", ip)
	}

	// Get the list of network interfaces
	ifaces, err := netImpl.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Find the interface with the given IP address
	for _, iface := range ifaces {
		// Get all addresses associated with the interface
		addrs, err := netImpl.Addrs(iface)
		if err != nil {
			return "", fmt.Errorf("failed to get interface addresses: %v", err)
		}

		// Check if any of the addresses match the given IP address
		for _, addr := range addrs {
			// Check if the address is an IPNet
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Check if the address matches the given IP address
			if ipNet.IP.Equal(net.ParseIP(ip)) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("interface with IP address %s not found", ip)
}
