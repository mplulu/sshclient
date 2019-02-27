package sshclient

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Client struct {
	client                         *ssh.Client
	sess                           *ssh.Session
	username, password, host, port string

	stdout *Writer

	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader
}

func NewClient(username, password, host, port string) *Client {
	client := &Client{
		username: username,
		password: password,
		host:     host,
		port:     port,

		stdout: &Writer{},
	}
	finish := make(chan bool)
	go client.connect(finish)
	<-finish
	return client
}

func (c *Client) connect(finish chan bool) {
	callback, method := c.getAuthMethodPublicKeys()
	// SSH client config
	config := &ssh.ClientConfig{
		User: c.username,
		Auth: []ssh.AuthMethod{
			method,
			ssh.Password(c.password),
		},
		// Non-production only
		HostKeyCallback: callback,
	}

	// Connect to host
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", c.host, c.port), config)
	if err != nil {
		panic(err)
	}
	c.client = client
	finish <- true
}

func (c *Client) createNewSession() *ssh.Session {
	session, err := c.client.NewSession()
	if err != nil {
		panic(err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		panic(err)
	}

	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}

	writer := NewPasswordPromptWriter(in, c.username, c.password)
	session.Stdout = writer
	session.Stderr = writer

	return session
}

func (c *Client) Run(cmd string, a ...interface{}) {
	session := c.createNewSession()
	defer session.Close()
	err := session.Run(fmt.Sprintf(cmd, a...))
	if err != nil {
		panic(err)
	}

}

func (c *Client) PromptRun(suffixList, answerList []string, cmd string, a ...interface{}) {
	session := c.createNewSession()
	defer session.Close()

	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}
	writer := NewPromptWriter(in, suffixList, answerList)
	session.Stdout = writer
	session.Stderr = writer
	err = session.Run(fmt.Sprintf(cmd, a...))
	if err != nil {
		panic(err)
	}
}

func (c *Client) Output(cmd string) string {
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}

	return stdoutBuf.String()
}

func (c *Client) OutputIgnoreError(cmd string) string {
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Run(cmd)
	return stdoutBuf.String()
}

func (c *Client) SUDORun(cmd string, a ...interface{}) {
	session := c.createNewSession()
	defer session.Close()
	err := session.Run(fmt.Sprintf("sudo %s", fmt.Sprintf(cmd, a...)))
	if err != nil {
		panic(err)
	}
}

func (c *Client) SUDOWriteToFile(content, filePath string) {
	session := c.createNewSession()
	defer session.Close()

	cmd := fmt.Sprintf("echo '%s' | sudo tee %s", content, filePath)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
}

func (c *Client) WriteToFile(content, filePath string) {
	session := c.createNewSession()
	defer session.Close()

	cmd := fmt.Sprintf("echo '%s' | tee %s", content, filePath)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
}

func (c *Client) AppendToFile(content, filePath string) {
	session := c.createNewSession()
	defer session.Close()

	cmd := fmt.Sprintf("echo '%s' >> %s", content, filePath)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
}

func (c *Client) IsFileExist(filePath string) bool {
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	cmd := fmt.Sprintf("(ls %s >> /dev/null 2>&1 && echo true) || echo false", filePath)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(stdoutBuf.String()) == "true"
}

func (c *Client) PromptCreateNewPassword(password, cmd string, a ...interface{}) {
	session := c.createNewSession()
	defer session.Close()

	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}

	writer := &CreateNewPasswordWriter{
		stdin:    in,
		password: password,
	}
	session.Stdout = writer
	session.Stderr = writer
	err = session.Run(fmt.Sprintf(cmd, a...))
	if err != nil {
		panic(err)
	}
}

func (c *Client) Exit() {
	session := c.createNewSession()
	defer session.Close()
	err := session.Run("exit")
	if err != nil {
		panic(err)
	}
}

func SSHCopyId(username, password, host, port string) {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	pubKeyContent, err := ioutil.ReadFile(filepath.Join(user.HomeDir, ".ssh", "id_rsa.pub"))
	if err != nil {
		panic(err)
	}
	client := NewClient(username, password, host, port)
	client.Run("mkdir -p ~/.ssh")
	client.AppendToFile(string(pubKeyContent), "~/.ssh/authorized_keys")
	client.Exit()
}
