package tailutils

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockNetwork is a mock implementation of the Network interface.
type MockNetwork struct {
	mock.Mock
}

func (m *MockNetwork) ParseCIDR(s string) (*net.IP, *net.IPNet, error) {
	args := m.Called(s)
	if args.Get(0) != nil {
		return args.Get(0).(*net.IP), args.Get(1).(*net.IPNet), args.Error(2)
	}
	return nil, nil, args.Error(2)
}

func (m *MockNetwork) Interfaces() ([]net.Interface, error) {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).([]net.Interface), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockNetwork) Addrs(iface net.Interface) ([]net.Addr, error) {
	args := m.Called(iface)
	if args.Get(0) != nil {
		return args.Get(0).([]net.Addr), args.Error(1)
	}
	return nil, args.Error(1)
}

func TestGetTailscaleIP_Success(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IP)
	ethIP := net.ParseIP("192.168.1.10")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(24, 32),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Mock Addrs for tailscale0 (Tailscale IP)
	tailscaleIP := net.ParseIP("100.64.0.1")
	tailscaleAddr := &net.IPNet{
		IP:   tailscaleIP,
		Mask: net.CIDRMask(10, 32),
	}
	mockNet.On("Addrs", ifaces[1]).Return([]net.Addr{tailscaleAddr}, nil)

	// Execute the function
	ipStr, err := getTailscaleIP(mockNet)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "100.64.0.1", ipStr)

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestGetTailscaleIP_NoTailscaleInterface(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
		{
			Name:  "lo",
			Flags: net.FlagUp | net.FlagLoopback,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IP)
	ethIP := net.ParseIP("192.168.1.10")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(24, 32),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Since tailscale0 is not present, no need to mock its Addrs

	// Execute the function
	ipStr, err := getTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.EqualError(t, err, "tailscale interface not found")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestGetTailscaleIP_ParseCIDRError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR to return an error when called with "100.64.0.0/10"
	tsCIDR := "100.64.0.0/10"
	mockNet.On("ParseCIDR", tsCIDR).Return((*net.IP)(nil), (*net.IPNet)(nil), errors.New("invalid CIDR"))

	// Execute the function
	ipStr, err := getTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to parse Tailscale IP range")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestGetTailscaleIP_InterfacesError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces to return an error
	mockNet.On("Interfaces").Return(nil, errors.New("interface error"))

	// Execute the function
	ipStr, err := getTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to get network interfaces")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestGetTailscaleIP_AddrsError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs to return an error for tailscale0
	mockNet.On("Addrs", ifaces[0]).Return(nil, errors.New("addrs error"))

	// Execute the function
	ipStr, err := getTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to get interface addresses")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestHasTailscaleIP_Exists(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for tailscale0
	tailscaleIP := net.ParseIP("100.64.0.1")
	tailscaleAddr := &net.IPNet{
		IP:   tailscaleIP,
		Mask: net.CIDRMask(10, 32),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{tailscaleAddr}, nil)

	// Execute the function
	exists, err := hasTailscaleIP(mockNet)

	// Assertions
	assert.NoError(t, err)
	assert.True(t, exists)

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestHasTailscaleIP_DoesNotExist(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR
	tsCIDR := "100.64.0.0/10"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IP)
	ethIP := net.ParseIP("192.168.1.10")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(24, 32),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Execute the function
	exists, err := hasTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.False(t, exists)
	assert.EqualError(t, err, "tailscale interface not found")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

func TestHasTailscaleIP_GetTailscaleIPError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR to return an error when called with "100.64.0.0/10"
	tsCIDR := "100.64.0.0/10"
	mockNet.On("ParseCIDR", tsCIDR).Return((*net.IP)(nil), (*net.IPNet)(nil), errors.New("parse CIDR error"))

	// Execute the function
	exists, err := hasTailscaleIP(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "failed to parse Tailscale IP range")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestGetTailscaleIP6_Success tests the successful retrieval of a Tailscale IPv6 address.
func TestGetTailscaleIP6_Success(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IPv6)
	ethIP := net.ParseIP("2001:db8::1")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(64, 128),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Mock Addrs for tailscale0 (Tailscale IPv6)
	tailscaleIP := net.ParseIP("fd7a:115c:a1e0::1")
	tailscaleAddr := &net.IPNet{
		IP:   tailscaleIP,
		Mask: net.CIDRMask(48, 128),
	}
	mockNet.On("Addrs", ifaces[1]).Return([]net.Addr{tailscaleAddr}, nil)

	// Execute the function
	ipStr, err := getTailscaleIP6(mockNet)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "fd7a:115c:a1e0::1", ipStr)

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestGetTailscaleIP6_NoTailscaleInterface tests the scenario where no Tailscale IPv6 interface is found.
func TestGetTailscaleIP6_NoTailscaleInterface(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces without a Tailscale interface
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
		{
			Name:  "lo",
			Flags: net.FlagUp | net.FlagLoopback,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IPv6)
	ethIP := net.ParseIP("2001:db8::1")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(64, 128),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Since tailscale0 is not present, no need to mock its Addrs

	// Execute the function
	ipStr, err := getTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.EqualError(t, err, "tailscale IPv6 interface not found")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestGetTailscaleIP6_ParseCIDRError tests the scenario where ParseCIDR returns an error.
func TestGetTailscaleIP6_ParseCIDRError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR to return an error when called with "fd7a:115c:a1e0::/48"
	tsCIDR := "fd7a:115c:a1e0::/48"
	mockNet.On("ParseCIDR", tsCIDR).Return((*net.IP)(nil), (*net.IPNet)(nil), errors.New("invalid CIDR"))

	// Execute the function
	ipStr, err := getTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to parse Tailscale IPv6 range")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestGetTailscaleIP6_InterfacesError tests the scenario where retrieving interfaces returns an error.
func TestGetTailscaleIP6_InterfacesError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces to return an error
	mockNet.On("Interfaces").Return(nil, errors.New("interface error"))

	// Execute the function
	ipStr, err := getTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to get network interfaces")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestGetTailscaleIP6_AddrsError tests the scenario where retrieving addresses for an interface returns an error.
func TestGetTailscaleIP6_AddrsError(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces with tailscale0
	ifaces := []net.Interface{
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs to return an error for tailscale0
	mockNet.On("Addrs", ifaces[0]).Return(nil, errors.New("addrs error"))

	// Execute the function
	ipStr, err := getTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.Equal(t, "", ipStr)
	assert.Contains(t, err.Error(), "failed to get interface addresses")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestHasTailscaleIP6_Exists tests that HasTailscaleIP6 returns true when a Tailscale IPv6 interface exists.
func TestHasTailscaleIP6_Exists(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces with tailscale0
	ifaces := []net.Interface{
		{
			Name:  "tailscale0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for tailscale0 (Tailscale IPv6)
	tailscaleIP := net.ParseIP("fd7a:115c:a1e0::1")
	tailscaleAddr := &net.IPNet{
		IP:   tailscaleIP,
		Mask: net.CIDRMask(48, 128),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{tailscaleAddr}, nil)

	// Execute the function
	exists, err := hasTailscaleIP6(mockNet)

	// Assertions
	assert.NoError(t, err)
	assert.True(t, exists)

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestHasTailscaleIP6_DoesNotExist tests that HasTailscaleIP6 returns false when no Tailscale IPv6 interface exists.
func TestHasTailscaleIP6_DoesNotExist(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR for IPv6
	tsCIDR := "fd7a:115c:a1e0::/48"
	ip, ipNet, _ := net.ParseCIDR(tsCIDR)
	mockNet.On("ParseCIDR", tsCIDR).Return(&ip, ipNet, nil)

	// Mock Interfaces without a Tailscale interface
	ifaces := []net.Interface{
		{
			Name:  "eth0",
			Flags: net.FlagUp,
		},
	}
	mockNet.On("Interfaces").Return(ifaces, nil)

	// Mock Addrs for eth0 (non-Tailscale IPv6)
	ethIP := net.ParseIP("2001:db8::1")
	ethAddr := &net.IPNet{
		IP:   ethIP,
		Mask: net.CIDRMask(64, 128),
	}
	mockNet.On("Addrs", ifaces[0]).Return([]net.Addr{ethAddr}, nil)

	// Execute the function
	exists, err := hasTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.False(t, exists)
	assert.EqualError(t, err, "tailscale IPv6 interface not found")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}

// TestHasTailscaleIP6_GetTailscaleIP6Error tests that HasTailscaleIP6 handles errors from getTailscaleIP6 correctly.
func TestHasTailscaleIP6_GetTailscaleIP6Error(t *testing.T) {
	mockNet := new(MockNetwork)

	// Mock ParseCIDR to return an error when called with "fd7a:115c:a1e0::/48"
	tsCIDR := "fd7a:115c:a1e0::/48"
	mockNet.On("ParseCIDR", tsCIDR).Return((*net.IP)(nil), (*net.IPNet)(nil), errors.New("parse CIDR error"))

	// Execute the function
	exists, err := hasTailscaleIP6(mockNet)

	// Assertions
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "failed to parse Tailscale IPv6 range")

	// Ensure all expectations were met
	mockNet.AssertExpectations(t)
}
