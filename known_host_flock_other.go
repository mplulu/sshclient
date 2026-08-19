//go:build !unix

package sshclient

import "os"

func lockKnownHostsFile(f *os.File) error {
	return nil
}

func unlockKnownHostsFile(f *os.File) error {
	return nil
}
