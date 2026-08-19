//go:build unix

package sshclient

import (
	"os"
)

func lockKnownHostsFile(f *os.File) error {
	// return unix.Flock(int(f.Fd()), unix.LOCK_EX)
	// currently will not lock
	return nil
}

func unlockKnownHostsFile(f *os.File) error {
	// return unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return nil
}
