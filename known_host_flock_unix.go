//go:build unix

package sshclient

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockKnownHostsFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func unlockKnownHostsFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
