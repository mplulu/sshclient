package sshclient

import (
	"io/ioutil"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func (c *Client) getAuthMethodPublicKeys() (authMethod ssh.AuthMethod, err error) {
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	keyFilePath := filepath.Join(c.getSSHFolderPath(), "id_rsa")
	if c.sshKeyPem != "" {
		keyFilePath = c.sshKeyPem
	}
	key, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, err
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}
