package sshclient

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var knownHostsMu sync.Mutex

type fakePublicKey struct{}

func (k *fakePublicKey) Type() string {
	return "fake-key-type"
}

func (k *fakePublicKey) Marshal() []byte {
	return []byte("fake-key")
}

func (k *fakePublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return errors.New("fake public key")
}

func (c *Client) createKnownHosts() {
	f, err := os.OpenFile(filepath.Join(c.getSSHFolderPath(), "known_hosts"), os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	f.Close()
}

func (c *Client) checkKnownHosts() ssh.HostKeyCallback {
	start := time.Now()
	sshPrint("checkKnownHosts start")
	c.createKnownHosts()
	parseStart := time.Now()
	sshPrint("knownhosts.New start")
	kh, err := knownhosts.New(filepath.Join(c.getSSHFolderPath(), "known_hosts"))
	sshPrint(fmt.Sprintf("knownhosts.New done took %s", time.Since(parseStart)))
	if err != nil {
		panic(err)
	}
	sshPrint(fmt.Sprintf("checkKnownHosts done took %s", time.Since(start)))
	return kh
}

func (c *Client) hostKeyAlgorithms(hostWithPort string) []string {
	start := time.Now()
	sshPrint("hostKeyAlgorithms lock start")
	knownHostsMu.Lock()
	sshPrint(fmt.Sprintf("hostKeyAlgorithms lock done took %s", time.Since(start)))
	defer knownHostsMu.Unlock()

	return hostKeyAlgorithmsFromCallback(c.checkKnownHosts(), hostWithPort)
}

func hostKeyAlgorithmsFromCallback(kh ssh.HostKeyCallback, hostWithPort string) []string {
	start := time.Now()
	sshPrint("hostKeyAlgorithmsFromCallback start")
	defer func() {
		sshPrint(fmt.Sprintf("hostKeyAlgorithmsFromCallback done took %s", time.Since(start)))
	}()
	dummy := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
	err := kh(hostWithPort, dummy, &fakePublicKey{})
	sshPrint(fmt.Sprintf("hostKeyAlgorithmsFromCallback lookup took %s", time.Since(start)))
	if err == nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		return nil
	}

	seen := map[string]bool{}
	algos := []string{}
	for _, known := range keyErr.Want {
		for _, algo := range algorithmsForKeyType(known.Key.Type()) {
			if seen[algo] {
				continue
			}
			seen[algo] = true
			algos = append(algos, algo)
		}
	}
	if len(algos) == 0 {
		return nil
	}
	return algos
}

func algorithmsForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

func (c *Client) hostKeyCallback(host string, remote net.Addr, pubKey ssh.PublicKey) error {
	start := time.Now()
	sshPrint("hostKeyCallback start")
	defer func() {
		sshPrint(fmt.Sprintf("hostKeyCallback done took %s", time.Since(start)))
	}()
	lockStart := time.Now()
	sshPrint("hostKeyCallback mutex lock start")
	knownHostsMu.Lock()
	sshPrint(fmt.Sprintf("hostKeyCallback mutex lock done took %s", time.Since(lockStart)))
	defer knownHostsMu.Unlock()

	c.createKnownHosts()
	khFilePath := filepath.Join(c.getSSHFolderPath(), "known_hosts")
	f, err := os.OpenFile(khFilePath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	flockStart := time.Now()
	sshPrint("lockKnownHostsFile start")
	if err := lockKnownHostsFile(f); err != nil {
		return err
	}
	sshPrint(fmt.Sprintf("lockKnownHostsFile done took %s", time.Since(flockStart)))
	defer unlockKnownHostsFile(f)

	kh := c.checkKnownHosts()
	lookupStart := time.Now()
	sshPrint("known_hosts lookup start")
	hErr := kh(host, remote, pubKey)
	sshPrint(fmt.Sprintf("known_hosts lookup done took %s", time.Since(lookupStart)))
	if hErr == nil {
		Log("Pub key exists for %s.", host)
		return nil
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(hErr, &keyErr) {
		return hErr
	}

	if len(keyErr.Want) > 0 {
		Log("WARNING: %v is not a key of %s, either a MiTM attack or %s has reconfigured the host pub key.", string(pubKey.Marshal()), host, host)
		return keyErr
	}

	Log("WARNING: %s is not trusted, adding this key: %q to known_hosts file.", host, string(pubKey.Marshal()))
	appendStart := time.Now()
	sshPrint("appendHostKey start")
	err = c.appendHostKey(f, host, remote, pubKey)
	sshPrint(fmt.Sprintf("appendHostKey done took %s", time.Since(appendStart)))
	return err
}

func uniqueKnownHostsAddrs(host string, remote net.Addr) []string {
	seen := map[string]bool{}
	addrs := []string{}
	appendAddr := func(addr string) {
		if addr == "" {
			return
		}
		normalized := knownhosts.Normalize(addr)
		if normalized == "" || seen[normalized] {
			return
		}
		seen[normalized] = true
		addrs = append(addrs, normalized)
	}
	appendAddr(host)
	if remote != nil {
		appendAddr(remote.String())
	}
	return addrs
}

func serializedHostKey(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + base64.StdEncoding.EncodeToString(pubKey.Marshal())
}

func hostKeyAlreadyStored(existing string, addrs []string, pubKey ssh.PublicKey) bool {
	line := knownhosts.Line(addrs, pubKey)
	keyPart := serializedHostKey(pubKey)
	addrSet := map[string]bool{}
	for _, addr := range addrs {
		addrSet[addr] = true
	}

	for _, existingLine := range strings.Split(existing, "\n") {
		existingLine = strings.TrimSpace(existingLine)
		if existingLine == "" || strings.HasPrefix(existingLine, "#") {
			continue
		}
		if existingLine == line {
			return true
		}

		fields := strings.Fields(existingLine)
		if len(fields) < 3 {
			continue
		}
		if strings.HasPrefix(fields[0], "@") || strings.HasPrefix(fields[0], "|") {
			continue
		}
		if fields[1]+" "+fields[2] != keyPart {
			continue
		}
		for _, existingHost := range strings.Split(fields[0], ",") {
			if addrSet[existingHost] {
				return true
			}
		}
	}
	return false
}

func (c *Client) appendHostKey(f *os.File, host string, remote net.Addr, pubKey ssh.PublicKey) error {
	addrs := uniqueKnownHostsAddrs(host, remote)
	if len(addrs) == 0 {
		return nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	existing, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if hostKeyAlreadyStored(string(existing), addrs, pubKey) {
		return nil
	}

	line := knownhosts.Line(addrs, pubKey)
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	_, fileErr := f.WriteString(fmt.Sprintf("%v\n", line))
	return fileErr
}

func (c *Client) getSSHFolderPath() string {
	sshFolderPath := c.sshFolderPath
	if sshFolderPath == "" {
		sshFolderPath = SSHFolderPathPackage
		if sshFolderPath == "" {
			homeDir := os.Getenv("HOME")
			sshFolderPath = filepath.Join(homeDir, ".ssh")
		}

	}
	return sshFolderPath
}
