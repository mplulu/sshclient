package sshclient

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ForceSSH disables the local exec shortcut, so 127.0.0.1/localhost are dialed over ssh like any other host.
// It is the rollback switch in case local exec misbehaves on a server.
var ForceSSH bool

func SetForceSSH(force bool) {
	ForceSSH = force
}

const localBasePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// cmdSession is the part of *ssh.Session that Client uses, so every Client method works both over ssh and over local exec.
type cmdSession interface {
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
	RequestPty(term string, h, w int, termmodes ssh.TerminalModes) error
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.Reader, error)
	Run(cmd string) error
	Start(cmd string) error
	Shell() error
	Wait() error
	Close() error
}

type sshSession struct {
	*ssh.Session
}

func (s *sshSession) SetStdout(w io.Writer) {
	s.Stdout = w
}

func (s *sshSession) SetStderr(w io.Writer) {
	s.Stderr = w
}

func isLocalHost(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// connectOrLocal uses local exec for a local host and falls back to connect for everything else.
func (c *Client) connectOrLocal(connect func() error) error {
	if !isLocalHost(c.host) || ForceSSH {
		return connect()
	}
	current, err := user.Current()
	if err != nil {
		return err
	}
	// ssh used to run commands as c.username; local exec runs them as the process user, so both must match.
	if current.Username != c.username {
		return fmt.Errorf("sshclient: local exec for %s@%s but process runs as %s; run the process as %s or call SetForceSSH(true)",
			c.username, c.host, current.Username, c.username)
	}
	c.local = true
	c.localHomeDir = current.HomeDir
	sshPrint(fmt.Sprintf("connect local exec user=%s", current.Username))
	return nil
}

func (c *Client) newSession() (cmdSession, error) {
	if c.local {
		return &localSession{client: c}, nil
	}
	session, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	return &sshSession{Session: session}, nil
}

// sudo returns the sudo prefix. Without a usable password (local exec has no tty, or no password is set)
// sudo must fail fast with -n instead of waiting on a prompt nobody answers.
func (c *Client) sudo() string {
	if c.local || c.password == "" {
		return "sudo -n"
	}
	return "sudo"
}

// localEnv mimics a fresh ssh login: HOME/USER of the process user and a PATH that includes the sbin folders (nginx lives in /usr/sbin).
func (c *Client) localEnv() []string {
	env := []string{}
	path := localBasePath
	for _, kv := range os.Environ() {
		key := strings.SplitN(kv, "=", 2)[0]
		switch key {
		case "PATH":
			path = path + ":" + strings.TrimPrefix(kv, "PATH=")
		case "HOME", "USER", "LOGNAME":
		default:
			env = append(env, kv)
		}
	}
	return append(env,
		"HOME="+c.localHomeDir,
		"USER="+c.username,
		"LOGNAME="+c.username,
		"PATH="+path,
	)
}

func localShell() string {
	if _, err := os.Stat("/bin/bash"); err == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}

// localSession runs a command with os/exec and behaves like an ssh session without a pty.
type localSession struct {
	client *Client

	stdout, stderr   io.Writer
	stdinR, stdinW   *os.File
	stdoutR, stdoutW *os.File

	cmd    *exec.Cmd
	waited bool
}

func (s *localSession) SetStdout(w io.Writer) {
	s.stdout = w
}

func (s *localSession) SetStderr(w io.Writer) {
	s.stderr = w
}

func (s *localSession) RequestPty(term string, h, w int, termmodes ssh.TerminalModes) error {
	// no pty locally: sudo runs with -n, so nothing needs a terminal
	return nil
}

func (s *localSession) StdinPipe() (io.WriteCloser, error) {
	if s.stdinW != nil {
		return nil, errors.New("sshclient: Stdin already set")
	}
	if s.cmd != nil {
		return nil, errors.New("sshclient: StdinPipe after process started")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.stdinR, s.stdinW = r, w
	return w, nil
}

func (s *localSession) StdoutPipe() (io.Reader, error) {
	if s.stdoutR != nil {
		return nil, errors.New("sshclient: Stdout already set")
	}
	if s.cmd != nil {
		return nil, errors.New("sshclient: StdoutPipe after process started")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.stdoutR, s.stdoutW = r, w
	return r, nil
}

func (s *localSession) start(args ...string) error {
	if s.cmd != nil {
		return errors.New("sshclient: session already started")
	}
	cmd := exec.Command(localShell(), args...)
	cmd.Dir = s.client.localHomeDir
	cmd.Env = s.client.localEnv()
	cmd.Stdout = s.stdout
	cmd.Stderr = s.stderr
	// pass *os.File directly so exec does not spawn copy goroutines that Wait would block on
	if s.stdinR != nil {
		cmd.Stdin = s.stdinR
	}
	if s.stdoutW != nil {
		cmd.Stdout = s.stdoutW
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// the child holds its own copies of these ends now
	if s.stdinR != nil {
		s.stdinR.Close()
		s.stdinR = nil
	}
	if s.stdoutW != nil {
		s.stdoutW.Close()
		s.stdoutW = nil
	}
	s.cmd = cmd
	return nil
}

func (s *localSession) Start(cmd string) error {
	return s.start("-c", cmd)
}

func (s *localSession) Shell() error {
	return s.start()
}

func (s *localSession) Run(cmd string) error {
	if err := s.Start(cmd); err != nil {
		return err
	}
	return s.Wait()
}

func (s *localSession) Wait() error {
	if s.cmd == nil {
		return errors.New("sshclient: session not started")
	}
	if s.waited {
		return errors.New("sshclient: Wait called twice")
	}
	s.waited = true
	return s.cmd.Wait()
}

func (s *localSession) Close() error {
	if s.stdinW != nil {
		s.stdinW.Close()
		s.stdinW = nil
	}
	// Shell sessions are never waited by the caller; reap them once stdin is closed
	if s.cmd != nil && !s.waited {
		s.waited = true
		go s.cmd.Wait()
	}
	return nil
}

func (c *Client) localCopyFile(sourceFilePath, destFilePath string) error {
	src, err := os.Open(sourceFilePath)
	if err != nil {
		return err
	}
	defer src.Close()
	// same mode the scp upload sends
	dest, err := os.OpenFile(destFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		return err
	}
	_, err = io.Copy(dest, src)
	closeErr := dest.Close()
	if err != nil {
		return err
	}
	return closeErr
}
