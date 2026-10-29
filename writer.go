package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Writer struct {
}

func (w *Writer) Write(p []byte) (n int, err error) {
	n, err = os.Stdout.Write(p)
	return n, err
}

type PasswordPromptWriter struct {
	mutex sync.Mutex

	stdin    io.WriteCloser
	username string
	password string
}

func NewPasswordPromptWriter(stdin io.WriteCloser, username, password string) *PasswordPromptWriter {
	return &PasswordPromptWriter{
		stdin:    stdin,
		username: username,
		password: password,
	}
}

func (w *PasswordPromptWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	n, err = os.Stdout.Write(p)
	suffixList := []string{
		fmt.Sprintf("[sudo] password for %s: ", w.username),
		"Password: ",
		"'s password: ",
	}
	for _, suffix := range suffixList {
		if strings.HasSuffix(string(p), suffix) {
			w.stdin.Write([]byte(w.password + "\n"))
			break
		}
	}
	return n, err
}

type YesPromptWriter struct {
	mutex sync.Mutex

	stdin io.WriteCloser
}

func NewYesPromptWriter(stdin io.WriteCloser) *YesPromptWriter {
	return &YesPromptWriter{
		stdin: stdin,
	}
}

func (w *YesPromptWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	n, err = os.Stdout.Write(p)
	suffixList := []string{
		"(yes/no)? ",
	}
	for _, suffix := range suffixList {
		if strings.HasSuffix(string(p), suffix) {
			w.stdin.Write([]byte("yes" + "\n"))
			break
		}
	}
	return n, err
}

type SudoWriter struct {
	mutex sync.Mutex

	stdin    io.WriteCloser
	username string
	password string
}

func NewSudoWriter(stdin io.WriteCloser, username, password string) *SudoWriter {
	return &SudoWriter{
		stdin:    stdin,
		username: username,
		password: password,
	}
}

func (w *SudoWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	n, err = os.Stdout.Write(p)
	suffixList := []string{
		fmt.Sprintf("[sudo] password for %s: ", w.username),
		"Password: ",
	}
	for _, suffix := range suffixList {
		if strings.HasSuffix(string(p), suffix) {
			w.stdin.Write([]byte(w.password + "\n"))
			break
		}
	}
	return n, err
}

type singleWriter struct {
	b  bytes.Buffer
	mu sync.Mutex
}

func (w *singleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

type stdOutSingleWriter struct {
	mu sync.Mutex
}

func (w *stdOutSingleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return os.Stdout.Write(p)
}
