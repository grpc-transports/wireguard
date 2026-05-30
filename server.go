package wgtransport

import (
	"fmt"
	"log"
	"net"
	"net/netip"
)

// ServerConfig holds the WireGuard server configuration.
type ServerConfig struct {
	// Backend selects the WireGuard implementation. Default is
	// BackendUserspace (works on any OS, no privileges). Set
	// BackendKernel inside a Linux microVM with CONFIG_WIREGUARD to
	// drive the kernel module via wgctrl + netlink (faster, visible
	// to host tools, requires CAP_NET_ADMIN).
	Backend Backend
	// InterfaceName, when Backend=BackendKernel, names the wg* netdev
	// the bring-up creates (or reuses if already present). Empty →
	// auto-generated "wg-<random>". Ignored for BackendUserspace.
	InterfaceName string
	// PrivateKey is the path to a base64-encoded Curve25519 private key
	// (32 bytes, one line). Generated on first start if the file does not
	// exist.
	PrivateKeyPath string
	// LocalIP is this node's address on the overlay (e.g. 10.0.0.1).
	LocalIP netip.Addr
	// ListenPort is the UDP underlay port. Zero binds to an ephemeral port.
	ListenPort uint16
	// Peers lists the authorized clients. Used as-is when PeersPath is empty.
	Peers []Peer
	// PeersPath is an optional path to a peer file (see loadPeersFile). When
	// non-empty, peers from disk are appended to Peers.
	PeersPath string
	// MTU is the overlay MTU. Zero selects the default (1420).
	MTU int
	// Logger receives device-level messages. Defaults to log.Default().
	Logger *log.Logger
}

// ListenWireGuard brings up a WireGuard device (per ServerConfig.Backend),
// listens for TCP connections on addr (an "ip:port" on the overlay), and
// returns a net.Listener suitable for grpc.Server.Serve. Closing the
// returned listener also tears down the WireGuard device.
func ListenWireGuard(addr string, cfg ServerConfig) (net.Listener, error) {
	priv, err := loadOrCreatePrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}

	peers := cfg.Peers
	if cfg.PeersPath != "" {
		extra, err := loadPeersFile(cfg.PeersPath)
		if err != nil {
			return nil, fmt.Errorf("peers file: %w", err)
		}
		peers = append(peers, extra...)
	}

	net, err := bringUpDevice(cfg.Backend, cfg.InterfaceName, priv, cfg.LocalIP, cfg.ListenPort, peers, cfg.MTU, cfg.Logger)
	if err != nil {
		return nil, err
	}

	lis, err := net.ListenTCP(addr)
	if err != nil {
		net.Close()
		return nil, fmt.Errorf("listen overlay %s: %w", addr, err)
	}
	return &wgListener{Listener: lis, net: net}, nil
}

// wgListener wraps a backend listener so closing it also tears down the
// underlying WireGuard device.
type wgListener struct {
	net.Listener
	net wgNet
}

func (l *wgListener) Close() error {
	err := l.Listener.Close()
	l.net.Close()
	return err
}
