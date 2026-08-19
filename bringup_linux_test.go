//go:build linux

package wgtransport

import (
	"errors"
	"net/netip"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// hostCanRunKernelWireGuard reports whether err is the environment saying it
// cannot host a kernel WireGuard interface at all, as opposed to BringUp being
// wrong. Both causes below were measured, not assumed:
//
//   - EPERM -- no CAP_NET_ADMIN. The previous guard was os.Geteuid() != 0, and
//     being uid 0 is not the same thing as holding the capability: inside a
//     plain docker container the process IS root while Docker's default
//     capability set drops CAP_NET_ADMIN. That is exactly how the four
//     emulated lanes run, so the guard passed, BringUp returned "operation not
//     permitted", and every emulated arch was red.
//
//   - EPROTONOSUPPORT -- the capability is present but the kernel has no
//     WireGuard. Adding --cap-add=NET_ADMIN to the emulated lanes does NOT fix
//     them: it only changes the error to "open wgctrl: socket: protocol not
//     supported". Verified by running the riscv64 test binary under qemu both
//     ways.
//
// Anything else is a real failure and is reported as one.
func isEnvironmentWithoutKernelWireGuard(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.ENODEV)
}

// TestBringUp_KernelInterfaceLifecycle verifies the new public BringUp API
// for the kernel backend: the wg interface appears after BringUp and is
// gone after Close. Needs CAP_NET_ADMIN and a kernel WireGuard device;
// skipped cleanly where either is missing, and only there.
func TestBringUp_KernelInterfaceLifecycle(t *testing.T) {
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
		if isEnvironmentWithoutKernelWireGuard(err) {
			t.Skipf("no kernel WireGuard here (needs CAP_NET_ADMIN and the wireguard device): %v", err)
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
