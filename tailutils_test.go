package tailutils

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

// MockNetwork is a mock implementation of the Network interface for testing purposes.
type MockNetwork struct {
	ParseCIDRFunc  func(s string) (*net.IPNet, error)
	ParseIPFunc    func(s string) (net.IP, error)
	InterfacesFunc func() ([]net.Interface, error)
	AddrsFunc      func(iface net.Interface) ([]net.Addr, error)
}

func (m *MockNetwork) ParseCIDR(s string) (*net.IPNet, error) {
	return m.ParseCIDRFunc(s)
}

func (m *MockNetwork) ParseIP(s string) (net.IP, error) {
	return m.ParseIPFunc(s)
}

func (m *MockNetwork) Interfaces() ([]net.Interface, error) {
	return m.InterfacesFunc()
}

func (m *MockNetwork) Addrs(iface net.Interface) ([]net.Addr, error) {
	return m.AddrsFunc(iface)
}

// MockAddr is a mock implementation of net.Addr for testing purposes.
type MockAddr struct{}

func (m *MockAddr) Network() string { return "mock" }
func (m *MockAddr) String() string  { return "mockaddr" }

func TestGetTailscaleIP(t *testing.T) {
	// Define test cases covering IPv4, IPv6, and mismatched IP versions
	testCases := []struct {
		name           string
		cidr           string
		ipv6           bool
		interfaceFlags net.Flags
		interfaceName  string
		addresses      []net.Addr
		expectedIP     string
		expectError    bool
		errorMessage   string
	}{
		{
			name:           "Valid IPv4 Tailscale IP",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("100.64.12.34"),
					Mask: net.CIDRMask(10, 32),
				},
			},
			expectedIP:   "100.64.12.34",
			expectError:  false,
			errorMessage: "",
		},
		{
			name:           "Valid IPv6 Tailscale IP",
			cidr:           tailscaleIP6CIDR,
			ipv6:           true,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1234"),
					Mask: net.CIDRMask(48, 128),
				},
			},
			expectedIP:   "fd7a:115c:a1e0::1234",
			expectError:  false,
			errorMessage: "",
		},
		{
			name:           "CIDR is IPv4 but interface has IPv6 address",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1234"),
					Mask: net.CIDRMask(48, 128),
				},
			},
			expectedIP:   "",
			expectError:  true,
			errorMessage: "tailscale interface not found",
		},
		{
			name:           "CIDR is IPv6 but interface has IPv4 address",
			cidr:           tailscaleIP6CIDR,
			ipv6:           true,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("100.64.12.34"),
					Mask: net.CIDRMask(10, 32),
				},
			},
			expectedIP:   "",
			expectError:  true,
			errorMessage: "tailscale interface not found",
		},
		{
			name:           "Multiple Addresses with One Valid IPv4",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("100.64.12.34"),
					Mask: net.CIDRMask(10, 32),
				},
			},
			expectedIP:   "100.64.12.34",
			expectError:  false,
			errorMessage: "",
		},
		{
			name:           "Multiple Addresses with No Valid IPv4",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagUp,
			interfaceName:  "tailscale0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("192.168.1.1"),
					Mask: net.CIDRMask(24, 32),
				},
				&net.IPNet{
					IP:   net.ParseIP("10.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
			},
			expectedIP:   "",
			expectError:  true,
			errorMessage: "tailscale interface not found",
		},
		{
			name:           "Interface is Down",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagUp &^ 0, // Interface is down
			interfaceName:  "tailscale0",
			addresses:      []net.Addr{},
			expectedIP:     "",
			expectError:    true,
			errorMessage:   "tailscale interface not found",
		},
		{
			name:           "Interface is Loopback",
			cidr:           tailscaleIP4CIDR,
			ipv6:           false,
			interfaceFlags: net.FlagLoopback | net.FlagUp,
			interfaceName:  "lo0",
			addresses: []net.Addr{
				&net.IPNet{
					IP:   net.ParseIP("127.0.0.1"),
					Mask: net.CIDRMask(8, 32),
				},
			},
			expectedIP:   "",
			expectError:  true,
			errorMessage: "tailscale interface not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockNet := &MockNetwork{
				ParseCIDRFunc: func(s string) (*net.IPNet, error) {
					_, ipNet, err := net.ParseCIDR(s)
					return ipNet, err
				},
				InterfacesFunc: func() ([]net.Interface, error) {
					return []net.Interface{
						{
							Index: 1,
							Flags: tc.interfaceFlags,
							Name:  tc.interfaceName,
						},
					}, nil
				},
				AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
					if iface.Name == tc.interfaceName {
						return tc.addresses, nil
					}
					return nil, nil
				},
			}

			ip, err := getTailscaleIP(mockNet, tc.cidr)
			if tc.expectError {
				if err == nil {
					t.Fatalf("Expected error '%s' but got nil", tc.errorMessage)
				}
				if err.Error() != tc.errorMessage {
					t.Errorf("Expected error message '%s', got '%s'", tc.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Did not expect an error, but got: %v", err)
				}
				if ip != tc.expectedIP {
					t.Errorf("Expected IP '%s', got '%s'", tc.expectedIP, ip)
				}
			}
		})
	}
}

func TestGetTailscaleIP_ParseCIDR_Error(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			return nil, errors.New("ParseCIDR error")
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_Interfaces_Error(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return nil, errors.New("Interfaces error")
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_NoInterfaces(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "lo",
					Flags: net.FlagLoopback,
				},
			}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found' error, got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_Addrs_Error(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return nil, errors.New("Addrs error")
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil || err.Error() != "failed to get interface addresses: Addrs error" {
		t.Errorf("Expected 'Addrs error', got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_NoMatchingIP(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			ipNet := &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1),
				Mask: net.CIDRMask(24, 32),
			}
			return []net.Addr{ipNet}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found' error, got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_NonIPNetAddress(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return []net.Addr{&MockAddr{}}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP4CIDR)
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found' error, got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_IPv6Address(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			ipNet := &net.IPNet{
				IP:   net.ParseIP("fd7a:115c:a1e0::1"),
				Mask: net.CIDRMask(48, 128),
			}
			return []net.Addr{ipNet}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if ip != "fd7a:115c:a1e0::1" {
		t.Errorf("Expected 'fd7a:115c:a1e0::1', got %s", ip)
	}
}

func TestGetTailscaleIP6(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNet := &net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1"),
					Mask: net.CIDRMask(48, 128),
				}
				return []net.Addr{ipNet}, nil
			}
			return nil, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP := "fd7a:115c:a1e0::1"
	if ip != expectedIP {
		t.Errorf("Expected IP %s, got %s", expectedIP, ip)
	}
}

func TestHasTailscaleIP_BothIPv4IPv6(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNetIPv4 := &net.IPNet{
					IP:   net.IPv4(100, 64, 0, 1),
					Mask: net.CIDRMask(10, 32),
				}
				ipNetIPv6 := &net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1"),
					Mask: net.CIDRMask(48, 128),
				}
				return []net.Addr{ipNetIPv4, ipNetIPv6}, nil
			}
			return nil, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	hasIP, err := HasTailscaleIP()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !hasIP {
		t.Errorf("Expected true, got false")
	}
}

func TestHasTailscaleIP_OnlyIP4(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNetIPv4 := &net.IPNet{
					IP:   net.IPv4(100, 64, 0, 1),
					Mask: net.CIDRMask(10, 32),
				}
				return []net.Addr{ipNetIPv4}, nil
			}
			return nil, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	hasIP, err := HasTailscaleIP()
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found' error, got %v", err)
	}
	if hasIP {
		t.Errorf("Expected false, got true")
	}
}

func TestGetInterfaceName_TailscaleIPv4(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
				{
					Index: 2,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(100, 64, 0, 1),
						Mask: net.CIDRMask(10, 32),
					},
				}, nil
			} else if iface.Name == "eth0" {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(192, 168, 1, 10),
						Mask: net.CIDRMask(24, 32),
					},
				}, nil
			}
			return nil, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ifaceName, err := GetInterfaceName("100.64.0.1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if ifaceName != "tailscale0" {
		t.Errorf("Expected interface name tailscale0, got %s", ifaceName)
	}
}

func TestGetInterfaceName_TailscaleIPv6(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
				{
					Index: 2,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				return []net.Addr{
					&net.IPNet{
						IP:   net.ParseIP("fd7a:115c:a1e0::1"),
						Mask: net.CIDRMask(48, 128),
					},
				}, nil
			} else if iface.Name == "eth0" {
				return []net.Addr{
					&net.IPNet{
						IP:   net.IPv4(192, 168, 1, 10),
						Mask: net.CIDRMask(24, 32),
					},
				}, nil
			}
			return nil, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ifaceName, err := GetInterfaceName("fd7a:115c:a1e0::1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if ifaceName != "tailscale0" {
		t.Errorf("Expected interface name tailscale0, got %s", ifaceName)
	}
}

func TestGetInterfaceName_IPNotInTailscaleRange(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "192.168.1.10"
	_, err := GetInterfaceName(ip)
	expectedErr := "IP address 192.168.1.10 is not within the Tailscale IP range"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_IPNotFound(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(100, 64, 0, 2),
					Mask: net.CIDRMask(10, 32),
				},
			}, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.3"
	_, err := GetInterfaceName(ip)
	expectedErr := "interface with IP address 100.64.0.3 not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_ParseCIDRError(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			if s == tailscaleIP4CIDR {
				return nil, errors.New("ParseCIDR error")
			}
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.1"
	_, err := GetInterfaceName(ip)
	expectedErr := "failed to parse Tailscale IP range: ParseCIDR error"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_ParseCIDR6Error(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			if s == tailscaleIP6CIDR {
				return nil, errors.New("ParseCIDR error")
			}
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.1"
	_, err := GetInterfaceName(ip)
	expectedErr := "failed to parse Tailscale IPv6 range: ParseCIDR error"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_InterfacesError(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return nil, errors.New("Interfaces error")
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.1"
	_, err := GetInterfaceName(ip)
	expectedErr := "failed to get network interfaces: Interfaces error"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_AddrsError(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return nil, errors.New("Addrs error")
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.1"
	_, err := GetInterfaceName(ip)
	expectedErr := "failed to get interface addresses: Addrs error"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetInterfaceName_NonIPNetAddress(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return []net.Addr{&MockAddr{}}, nil
		},
	}

	oldDefaultNetwork := defaultNetwork
	defaultNetwork = mockNet
	defer func() {
		defaultNetwork = oldDefaultNetwork
	}()

	ip := "100.64.0.1"
	_, err := GetInterfaceName(ip)
	expectedErr := "interface with IP address 100.64.0.1 not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestGetTailscaleIP6_DirectInterfaceFail(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	// Create a mock network that won't list properly
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return nil, errors.New("Interfaces error")
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	if err == nil || err.Error() != "failed to get network interfaces: Interfaces error" {
		t.Errorf("Expected 'Interfaces error', got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP6_DirectIfaceDown(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	// Create a mock network that for some reason has a tailscale IP yet is labeled as loopback
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagLoopback,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(100, 64, 0, 1),
					Mask: net.CIDRMask(64, 128),
				},
			}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	// Expect "tailscale interface not found" error
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found', got %v", err)
	}

	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP6_DirectInvalidIP(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	// Create a mock network that will fail to get the interface IP
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return nil, errors.New("Addrs error")
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	if err == nil || err.Error() != "failed to get interface addresses: Addrs error" {
		t.Errorf("Expected 'Addrs error', got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP6_NonIPNetAddress(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "eth0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			// Return an address that is not a *net.IPNet
			return []net.Addr{&MockAddr{}}, nil
		},
	}

	ip, err := getTailscaleIP(mockNet, tailscaleIP6CIDR)
	if err == nil || err.Error() != "tailscale interface not found" {
		t.Errorf("Expected 'tailscale interface not found' error, got %v", err)
	}
	if ip != "" {
		t.Errorf("Expected empty IP, got %s", ip)
	}
}

func TestGetTailscaleIP_Public(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNet := &net.IPNet{
					IP:   net.IPv4(100, 64, 0, 1),
					Mask: net.CIDRMask(10, 32),
				}
				return []net.Addr{ipNet}, nil
			}
			return nil, nil
		},
	}

	defaultNetwork = mockNet

	ip, err := GetTailscaleIP()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP := "100.64.0.1"
	if ip != expectedIP {
		t.Errorf("Expected IP %s, got %s", expectedIP, ip)
	}
}

func TestGetTailscaleIP6_Public(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNet := &net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1"),
					Mask: net.CIDRMask(48, 128),
				}
				return []net.Addr{ipNet}, nil
			}
			return nil, nil
		},
	}

	defaultNetwork = mockNet

	ip, err := GetTailscaleIP6()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP := "fd7a:115c:a1e0::1"
	if ip != expectedIP {
		t.Errorf("Expected IP %s, got %s", expectedIP, ip)
	}
}

func TestGetTailscaleIP6_Errors(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					MTU:   1500,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			return nil, nil
		},
	}

	defaultNetwork = mockNet

	_, err := GetTailscaleIP6()
	expectedErr := "tailscale interface not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

func TestHasTailscaleIP_Public(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{
				{
					Index: 1,
					Name:  "tailscale0",
					Flags: net.FlagUp,
				},
			}, nil
		},
		AddrsFunc: func(iface net.Interface) ([]net.Addr, error) {
			if iface.Name == "tailscale0" {
				ipNetIPv4 := &net.IPNet{
					IP:   net.IPv4(100, 64, 0, 1),
					Mask: net.CIDRMask(10, 32),
				}
				ipNetIPv6 := &net.IPNet{
					IP:   net.ParseIP("fd7a:115c:a1e0::1"),
					Mask: net.CIDRMask(48, 128),
				}
				return []net.Addr{ipNetIPv4, ipNetIPv6}, nil
			}
			return nil, nil
		},
	}

	defaultNetwork = mockNet

	hasIP, err := HasTailscaleIP()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !hasIP {
		t.Errorf("Expected true, got false")
	}
}

func TestHasTailscaleIP_NoIPs(t *testing.T) {
	// Save the original defaultNetwork and restore it after the test
	originalNetwork := defaultNetwork
	defer func() { defaultNetwork = originalNetwork }()

	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, _ := net.ParseCIDR(s)
			return ipNet, nil
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return []net.Interface{}, nil
		},
	}

	defaultNetwork = mockNet

	hasIP, err := HasTailscaleIP()
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
	if hasIP {
		t.Errorf("Expected false, got true")
	}
}

func TestRealNetwork_ParseCIDR(t *testing.T) {
	rn := &realNetwork{}
	ipNet, err := rn.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP, expectedIPNet, _ := net.ParseCIDR("192.168.1.0/24")
	if !ipNet.IP.Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ipNet.IP)
	}
	if !reflect.DeepEqual(ipNet, expectedIPNet) {
		t.Errorf("Expected IPNet %v, got %v", expectedIPNet, ipNet)
	}
}

func TestRealNetwork_ParseIP(t *testing.T) {
	rn := &realNetwork{}
	ip, err := rn.ParseIP("192.168.1.1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP := net.ParseIP("192.168.1.1")
	if !ip.Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ip)
	}
}

func TestRealNetwork_ParseIPInvalidIP(t *testing.T) {
	rn := &realNetwork{}
	_, err := rn.ParseIP("192.168.1")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestRealNetwork_Interfaces(t *testing.T) {
	rn := &realNetwork{}
	_, err := rn.Interfaces()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	// We can't predict the interfaces, so just ensure it doesn't error
}

func TestRealNetwork_Addrs(t *testing.T) {
	rn := &realNetwork{}
	ifaces, err := rn.Interfaces()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	for _, iface := range ifaces {
		_, err := rn.Addrs(iface)
		if err != nil {
			t.Errorf("Expected no error for interface %s, got %v", iface.Name, err)
		}
		// We can't predict the addresses, so just ensure it doesn't error
	}
}

func TestParseIPFunc_InMockNetwork(t *testing.T) {
	mockNet := &MockNetwork{
		ParseIPFunc: func(s string) (net.IP, error) {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, errors.New("invalid IP")
			}
			return ip, nil
		},
	}

	ip, err := mockNet.ParseIP("192.168.1.1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedIP := net.ParseIP("192.168.1.1")
	if !ip.Equal(expectedIP) {
		t.Errorf("Expected IP %v, got %v", expectedIP, ip)
	}

	_, err = mockNet.ParseIP("invalid-ip")
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

// Test hasTailscaleIP function directly
func TestHasTailscaleIP_Direct(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
		InterfacesFunc: func() ([]net.Interface, error) {
			return nil, errors.New("Interfaces error")
		},
	}

	hasIP, err := hasTailscaleIP(mockNet)
	if err == nil || err.Error() != "failed to get network interfaces: Interfaces error" {
		t.Errorf("Expected 'Interfaces error', got %v", err)
	}
	if hasIP {
		t.Errorf("Expected false, got true")
	}
}

func TestHasTailscaleIP6_Direct(t *testing.T) {
	mockNet := &MockNetwork{
		ParseCIDRFunc: func(s string) (*net.IPNet, error) {
			if s == tailscaleIP6CIDR {
				return nil, errors.New("ParseCIDR error")
			}
			_, ipNet, err := net.ParseCIDR(s)
			return ipNet, err
		},
	}

	hasIP, err := hasTailscaleIP6(mockNet)
	// We're expecting a ParseCIDR error here
	if err == nil || err.Error() != "failed to parse Tailscale IP range: ParseCIDR error" {
		t.Errorf("Expected 'failed to parse Tailscale IP range: ParseCIDR error', got %v", err)
	}
	if hasIP {
		t.Errorf("Expected false, got true")
	}
}
