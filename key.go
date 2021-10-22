package sshclient

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (c *Client) getAuthMethodPublicKeys() (sshCallback ssh.HostKeyCallback, authMethod ssh.AuthMethod, err error) {

	sshFolderPath := c.sshFolderPath
	if sshFolderPath == "" {
		homeDir := os.Getenv("HOME")
		sshFolderPath = filepath.Join(homeDir, ".ssh")
	}
	// Every client must provide a host key check.  Here is a
	// simple-minded parse of OpenSSH's known_hosts file
	host := c.host
	file, err := os.Open(filepath.Join(sshFolderPath, "known_hosts"))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, nil, err
			}
			break
		}
	}

	if hostKey == nil {
		return nil, nil, errors.New(fmt.Sprintf("no host key at %v", sshFolderPath))
	}
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	keyFilePath := filepath.Join(sshFolderPath, "id_rsa")
	if c.sshKeyPem != "" {
		keyFilePath = c.sshKeyPem
	}
	key, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, err
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	return ssh.FixedHostKey(hostKey), ssh.PublicKeys(signer), nil
}
