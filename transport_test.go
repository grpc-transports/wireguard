package wgtransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── keygen ───────────────────────────────────────────────────────────────────

func TestNewPrivateKey_ClampedAnd32Bytes(t *testing.T) {
	priv, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("len = %d, want 32", len(priv))
	}
	if priv[0]&7 != 0 {
		t.Errorf("low 3 bits of byte 0 must be cleared, got %#x", priv[0])
	}
	if priv[31]&0x80 != 0 {
		t.Errorf("high bit of byte 31 must be cleared, got %#x", priv[31])
	}
	if priv[31]&0x40 == 0 {
		t.Errorf("bit 6 of byte 31 must be set, got %#x", priv[31])
	}
}

func TestPublicKey_Deterministic(t *testing.T) {
	priv, _ := newPrivateKey()
	pub1, err := publicKey(priv)
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	pub2, _ := publicKey(priv)
	if !bytes.Equal(pub1, pub2) {
		t.Error("publicKey not deterministic for same private key")
	}
	if len(pub1) != 32 {
		t.Errorf("public key len = %d, want 32", len(pub1))
	}
}

func TestLoadOrCreatePrivateKey_CreatesNew(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg_priv")
	priv, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("len = %d, want 32", len(priv))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("key file not persisted: %v", err)
	}
}

func TestLoadOrCreatePrivateKey_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg_priv")
	p1, _ := loadOrCreatePrivateKey(path)
	p2, err := loadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(p1, p2) {
		t.Error("reloaded key differs")
	}
}

func TestDecodeKey_BadLength(t *testing.T) {
	if _, err := decodeKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for short key")
	}
}

// ─── peers ────────────────────────────────────────────────────────────────────

func TestParsePeerLine_Minimal(t *testing.T) {
	priv, _ := newPrivateKey()
	pub, _ := publicKey(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	p, err := parsePeerLine(pubB64 + " 10.0.0.2/32")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.PublicKey != pubB64 {
		t.Errorf("pubkey = %q, want %q", p.PublicKey, pubB64)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.0.0.2/32" {
		t.Errorf("allowed-ips = %v", p.AllowedIPs)
	}
}

func TestParsePeerLine_Full(t *testing.T) {
	priv, _ := newPrivateKey()
	pub, _ := publicKey(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	line := pubB64 + " 10.0.0.0/24,10.1.0.0/24 1.2.3.4:51820 25"
	p, err := parsePeerLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("expected 2 allowed-ips, got %d", len(p.AllowedIPs))
	}
	if p.Endpoint != "1.2.3.4:51820" {
		t.Errorf("endpoint = %q", p.Endpoint)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d, want 25", p.PersistentKeepalive)
	}
}

func TestParsePeerLine_BadPubkey(t *testing.T) {
	if _, err := parsePeerLine("not-base64-key 10.0.0.2/32"); err == nil {
		t.Error("expected error for bad pubkey")
	}
}

func TestLoadPeersFile_EmptyPath(t *testing.T) {
	peers, err := loadPeersFile("")
	if err != nil || peers != nil {
		t.Errorf("empty path: got (%v, %v), want (nil, nil)", peers, err)
	}
}

func TestLoadPeersFile_MissingFile(t *testing.T) {
	peers, err := loadPeersFile("/non/existent/peers")
	if err != nil || peers != nil {
		t.Errorf("missing file: got (%v, %v), want (nil, nil)", peers, err)
	}
}

func TestLoadPeersFile_CommentsAndBlanks(t *testing.T) {
	priv, _ := newPrivateKey()
	pub, _ := publicKey(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	content := "# header comment\n" +
		"\n" +
		pubB64 + " 10.0.0.2/32\n" +
		"# inline comment\n"
	path := filepath.Join(t.TempDir(), "peers")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	peers, err := loadPeersFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}
}

// ─── UAPI config ──────────────────────────────────────────────────────────────

func TestBuildUAPIConfig_IncludesAllFields(t *testing.T) {
	priv, _ := newPrivateKey()
	peerPriv, _ := newPrivateKey()
	peerPub, _ := publicKey(peerPriv)

	cfg, err := buildUAPIConfig(priv, 51820, []Peer{{
		PublicKey:           base64.StdEncoding.EncodeToString(peerPub),
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
		Endpoint:            "1.2.3.4:51820",
		PersistentKeepalive: 25,
	}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		"private_key=",
		"listen_port=51820",
		"public_key=",
		"allowed_ip=10.0.0.2/32",
		"endpoint=1.2.3.4:51820",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("UAPI config missing %q\n%s", want, cfg)
		}
	}
}

func TestBuildUAPIConfig_SkipsListenPortZero(t *testing.T) {
	priv, _ := newPrivateKey()
	cfg, err := buildUAPIConfig(priv, 0, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if strings.Contains(cfg, "listen_port") {
		t.Errorf("expected no listen_port line, got:\n%s", cfg)
	}
}

// ─── addr ─────────────────────────────────────────────────────────────────────

func TestParseOverlayAddr_Valid(t *testing.T) {
	a, err := parseOverlayAddr("10.0.0.1:50051")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.Port != 50051 || a.IP.String() != "10.0.0.1" {
		t.Errorf("addr = %+v", a)
	}
}

func TestParseOverlayAddr_Invalid(t *testing.T) {
	if _, err := parseOverlayAddr("not-an-addr"); err == nil {
		t.Error("expected error for invalid addr")
	}
}

// ─── Integration: full client/server roundtrip over loopback ─────────────────

// TestIntegration_Roundtrip brings up two userspace WireGuard devices on
// loopback (different UDP ports), peers them, and verifies that a client TCP
// connection through netstack reaches a server listener through netstack.
func TestIntegration_Roundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (skipped in -short)")
	}

	dir := t.TempDir()
	serverKeyPath := filepath.Join(dir, "server_priv")
	clientKeyPath := filepath.Join(dir, "client_priv")

	serverPriv, err := loadOrCreatePrivateKey(serverKeyPath)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	clientPriv, err := loadOrCreatePrivateKey(clientKeyPath)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	serverPub, _ := publicKey(serverPriv)
	clientPub, _ := publicKey(clientPriv)
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPub)
	clientPubB64 := base64.StdEncoding.EncodeToString(clientPub)

	const serverPort = uint16(51820)
	serverIP := netip.MustParseAddr("10.6.6.1")
	clientIP := netip.MustParseAddr("10.6.6.2")

	lis, err := ListenWireGuard(fmt.Sprintf("%s:9001", serverIP), ServerConfig{
		PrivateKeyPath: serverKeyPath,
		LocalIP:        serverIP,
		ListenPort:     serverPort,
		Peers: []Peer{{
			PublicKey:  clientPubB64,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(clientIP, 32)},
		}},
	})
	if err != nil {
		t.Fatalf("ListenWireGuard: %v", err)
	}
	defer lis.Close()

	// Server-side: accept and echo.
	acceptDone := make(chan error, 1)
	const payload = "hello wireguard"
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			acceptDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			acceptDone <- err
			return
		}
		if _, err := conn.Write(buf); err != nil {
			acceptDone <- err
			return
		}
		acceptDone <- nil
	}()

	// Client side: bring up a second device and dial through the backend's
	// wgNet abstraction. The test exercises the userspace backend by default
	// (BackendUserspace=0); the kernel backend is excluded here since
	// hitting wg kernel module from a unit test needs CAP_NET_ADMIN.
	clientNet, err := bringUpDevice(
		BackendUserspace,
		"",
		clientPriv,
		clientIP,
		0,
		[]Peer{{
			PublicKey:           serverPubB64,
			AllowedIPs:          []netip.Prefix{netip.PrefixFrom(serverIP, 32)},
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
			PersistentKeepalive: 1,
		}},
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	defer clientNet.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := clientNet.DialContext(ctx, fmt.Sprintf("%s:9001", serverIP))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("got %q, want %q", buf, payload)
	}

	select {
	case err := <-acceptDone:
		if err != nil {
			t.Errorf("server side: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for server accept")
	}
}

// ─── wgListener ───────────────────────────────────────────────────────────────

func TestWGListener_CloseTearsDownDevice(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "priv")

	lis, err := ListenWireGuard("10.7.7.1:9000", ServerConfig{
		PrivateKeyPath: keyPath,
		LocalIP:        netip.MustParseAddr("10.7.7.1"),
		ListenPort:     0,
	})
	if err != nil {
		t.Fatalf("ListenWireGuard: %v", err)
	}
	if err := lis.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// A second Accept must fail now that the listener is closed.
	if _, err := lis.Accept(); err == nil || !isClosedErr(err) {
		t.Errorf("Accept after Close: err = %v, want net.ErrClosed", err)
	}
}

func isClosedErr(err error) bool {
	if err == net.ErrClosed {
		return true
	}
	msg := err.Error()
	// netstack signals a closed listener via "endpoint is in invalid state".
	return strings.Contains(msg, "closed") || strings.Contains(msg, "invalid state")
}
