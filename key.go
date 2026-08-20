package sshclient

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

func (c *Client) getAuthMethodPublicKeys() (authMethod ssh.AuthMethod, err error) {
	start := time.Now()
	sshPrint("getAuthMethodPublicKeys start")
	keyFilePath := filepath.Join(c.getSSHFolderPath(), "id_rsa")
	if c.sshKeyPem != "" {
		keyFilePath = c.sshKeyPem
	}
	readStart := time.Now()
	sshPrint("ReadFile id_rsa start")
	key, err := ioutil.ReadFile(keyFilePath)
	sshPrint(fmt.Sprintf("ReadFile id_rsa done took %s", time.Since(readStart)))
	if err != nil {
		sshPrint(fmt.Sprintf("getAuthMethodPublicKeys error took %s", time.Since(start)))
		return nil, err
	}

	parseStart := time.Now()
	sshPrint("ParsePrivateKey start")
	signer, err := ssh.ParsePrivateKey(key)
	sshPrint(fmt.Sprintf("ParsePrivateKey done took %s", time.Since(parseStart)))
	if err != nil {
		sshPrint(fmt.Sprintf("getAuthMethodPublicKeys error took %s", time.Since(start)))
		return nil, err
	}

	sshPrint(fmt.Sprintf("getAuthMethodPublicKeys done took %s", time.Since(start)))
	return ssh.PublicKeys(signer), nil
}
