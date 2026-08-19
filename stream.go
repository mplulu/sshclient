package sshclient

import (
	"sync"
)

type SingleStreamWriter struct {
	mu sync.Mutex
	ch chan []byte
}

func (w *SingleStreamWriter) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.ch <- cp
	return len(p), nil
}

func NewSingleStreamWriter(bufferSize int) *SingleStreamWriter {
	return &SingleStreamWriter{
		ch: make(chan []byte, bufferSize),
	}
}

func (c *Client) StreamOutput(command string) <-chan []byte {
	session := c.createNewSession()
	stdoutBuf := NewSingleStreamWriter(1024)
	session.Stdout = stdoutBuf
	session.Stderr = stdoutBuf

	err := session.Start(command)
	if err != nil {
		session.Close()
		panic(err)
	}

	go func() {
		session.Wait()
		session.Close()
		stdoutBuf.mu.Lock()
		close(stdoutBuf.ch)
		stdoutBuf.mu.Unlock()
	}()

	return stdoutBuf.ch
}
