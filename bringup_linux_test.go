//go:build linux

package wgtransport

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestBringUp_KernelInterfaceLifecycle verifies the new public BringUp API
// for the kernel backend: the wg interface appears after BringUp and is
// gone after Close.
//
// It needs a real netlink device + CAP_NET_ADMIN. That is absent on the
// default GitHub runner user, inside an unprivileged container, and under
// qemu-user emulation — in all of those cases creating the wg link fails with
// EPERM/EACCES (or, lacking euid 0, we don't even try). The test then skips
// cleanly instead of failing, so the userspace (gVisor netstack) suite below
// still validates every arch. On a privileged host it runs for real.
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
		// euid 0 but no CAP_NET_ADMIN (e.g. root inside an unprivileged
		// container or under qemu): the netlink RTM_NEWLINK is rejected.
		// Treat that as "not supported here" rather than a real failure.
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("kernel BringUp not permitted (no CAP_NET_ADMIN): %v", err)
		}
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
