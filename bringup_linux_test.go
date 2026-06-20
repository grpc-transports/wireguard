//go:build linux

package wgtransport

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestBringUp_KernelInterfaceLifecycle verifies the new public BringUp API
// for the kernel backend: the wg interface appears after BringUp and is
// gone after Close. Requires CAP_NET_ADMIN; skipped cleanly otherwise.
func TestBringUp_KernelInterfaceLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("kernel BringUp test needs CAP_NET_ADMIN (run as root)")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "priv")

	const ifname = "wg-bringup-t"
	cfg := ServerConfig{
		Backend:        BackendKernel,
		InterfaceName:  ifname,
		PrivateKeyPath: keyPath,
		LocalIP:        netip.MustParseAddr("10.55.0.1"),
		ListenPort:     0,
	}

	c, err := BringUp(cfg)
	if err != nil {
		t.Fatalf("BringUp: %v", err)
	}
	// Interface must be present right after BringUp returns.
	if _, err := netlink.LinkByName(ifname); err != nil {
		_ = c.Close()
		t.Fatalf("wg interface %s not found after BringUp: %v", ifname, err)
	}

	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// And gone after Close.
	if _, err := netlink.LinkByName(ifname); err == nil {
		// Best-effort cleanup so the test machine doesn't leak the netdev.
		if link, lerr := netlink.LinkByName(ifname); lerr == nil {
			_ = netlink.LinkDel(link)
		}
		t.Errorf("wg interface %s still present after Close", ifname)
	}
}
