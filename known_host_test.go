package sshclient

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{
		sshFolderPath: t.TempDir(),
		host:          "127.0.0.1",
		port:          "22",
	}
}

func testRemote() *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
}

func testEd25519Key(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func testECDSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func testRSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func knownHostsContent(t *testing.T, c *Client) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.getSSHFolderPath(), "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func countHostKeyLines(content string) int {
	n := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

func TestUniqueKnownHostsAddrsDedupsNormalizedHostAndRemote(t *testing.T) {
	addrs := uniqueKnownHostsAddrs("127.0.0.1:22", testRemote())
	if len(addrs) != 1 || addrs[0] != "127.0.0.1" {
		t.Fatalf("got %v", addrs)
	}
}

func TestUniqueKnownHostsAddrsKeepsHostnameAndIP(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("141.230.0.70"), Port: 22}
	addrs := uniqueKnownHostsAddrs("staging.example:22", remote)
	if len(addrs) != 2 || addrs[0] != "staging.example" || addrs[1] != "141.230.0.70" {
		t.Fatalf("got %v", addrs)
	}
}

func TestHostKeyAlreadyStoredMatchesHostOnCombinedLine(t *testing.T) {
	key := testECDSAKey(t)
	existing := knownhosts.Line([]string{"github.com", "127.0.0.1"}, key) + "\n"
	if !hostKeyAlreadyStored(existing, []string{"127.0.0.1"}, key) {
		t.Fatal("expected combined line to cover 127.0.0.1")
	}
}

func TestHostKeyCallbackAddsUnknownHostOnce(t *testing.T) {
	c := newTestClient(t)
	key := testECDSAKey(t)
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), key); err != nil {
		t.Fatal(err)
	}
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), key); err != nil {
		t.Fatal(err)
	}
	content := knownHostsContent(t, c)
	if countHostKeyLines(content) != 1 {
		t.Fatalf("expected 1 line, got %q", content)
	}
}

func TestHostKeyCallbackRejectsSameTypeMismatch(t *testing.T) {
	c := newTestClient(t)
	oldKey := testECDSAKey(t)
	newKey := testECDSAKey(t)
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), oldKey); err != nil {
		t.Fatal(err)
	}
	err := c.hostKeyCallback("127.0.0.1:22", testRemote(), newKey)
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		t.Fatalf("expected key mismatch, got %v", err)
	}
	if countHostKeyLines(knownHostsContent(t, c)) != 1 {
		t.Fatal("mismatch should not append a new line")
	}
}

func TestHostKeyCallbackRejectsNewKeyTypeForKnownHost(t *testing.T) {
	c := newTestClient(t)
	ecdsaKey := testECDSAKey(t)
	ed25519Key := testEd25519Key(t)
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), ecdsaKey); err != nil {
		t.Fatal(err)
	}
	err := c.hostKeyCallback("127.0.0.1:22", testRemote(), ed25519Key)
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		t.Fatalf("expected key mismatch for new type, got %v", err)
	}
	if countHostKeyLines(knownHostsContent(t, c)) != 1 {
		t.Fatal("new key type should not be appended for a known host")
	}
}

func TestHostKeyAlgorithmsPrefersKnownECDSA(t *testing.T) {
	c := newTestClient(t)
	key := testECDSAKey(t)
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), key); err != nil {
		t.Fatal(err)
	}
	algos := c.hostKeyAlgorithms("127.0.0.1:22")
	if len(algos) != 1 || algos[0] != ssh.KeyAlgoECDSA256 {
		t.Fatalf("got %v", algos)
	}
}

func TestHostKeyAlgorithmsUnknownHostIsNil(t *testing.T) {
	c := newTestClient(t)
	c.createKnownHosts()
	if algos := c.hostKeyAlgorithms("127.0.0.1:22"); algos != nil {
		t.Fatalf("expected nil, got %v", algos)
	}
}

func TestHostKeyAlgorithmsExpandsRSA(t *testing.T) {
	c := newTestClient(t)
	key := testRSAKey(t)
	if err := c.hostKeyCallback("127.0.0.1:22", testRemote(), key); err != nil {
		t.Fatal(err)
	}
	algos := c.hostKeyAlgorithms("127.0.0.1:22")
	if len(algos) != 3 {
		t.Fatalf("got %v", algos)
	}
	if algos[0] != ssh.KeyAlgoRSASHA256 || algos[1] != ssh.KeyAlgoRSASHA512 || algos[2] != ssh.KeyAlgoRSA {
		t.Fatalf("got %v", algos)
	}
}

func TestHostKeyCallbackConcurrentWritesDoNotDuplicate(t *testing.T) {
	c := newTestClient(t)
	key := testECDSAKey(t)
	wg := sync.WaitGroup{}
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- c.hostKeyCallback("127.0.0.1:22", testRemote(), key)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	content := knownHostsContent(t, c)
	if countHostKeyLines(content) != 1 {
		t.Fatalf("expected 1 line, got %q", content)
	}
}
