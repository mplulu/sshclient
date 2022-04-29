package sshclient

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (c *Client) createKnownHosts() {
	f, err := os.OpenFile(filepath.Join(c.getSSHFolderPath(), "known_hosts"), os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	f.Close()
}

func (c *Client) checkKnownHosts() ssh.HostKeyCallback {
	c.createKnownHosts()
	kh, err := knownhosts.New(filepath.Join(c.getSSHFolderPath(), "known_hosts"))
	if err != nil {
		panic(err)
	}
	return kh
}

func (c *Client) addHostKey(host string, remote net.Addr, pubKey ssh.PublicKey) error {
	// add host key if host is not found in known_hosts, error object is return, if nil then connection proceeds,
	// if not nil then connection stops.
	khFilePath := filepath.Join(c.sshFolderPath, "known_hosts")

	f, fErr := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if fErr != nil {
		return fErr
	}
	defer f.Close()

	knownHosts := knownhosts.Normalize(remote.String())
	_, fileErr := f.WriteString(fmt.Sprintf("%v\n", knownhosts.Line([]string{knownHosts}, pubKey)))
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
