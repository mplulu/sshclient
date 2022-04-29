package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"golang.org/x/crypto/ssh"
)

var SSHFolderPathPackage string

func SetSSHFolderPath(sshFolderPath string) {
	SSHFolderPathPackage = sshFolderPath
}

var clientList []*Client

func init() {
	clientList = []*Client{}
	go schedulePrintClientCount()
}

type Client struct {
	client                                                   *ssh.Client
	sess                                                     *ssh.Session
	username, password, sshFolderPath, sshKeyPem, host, port string
	knownHost                                                bool

	stdout *Writer

	stdinPipe  io.WriteCloser
	stdoutPipe io.Reader

	stackLog string
}

func NewClient(username, password, host, port string) (*Client, error) {
	client := &Client{
		username: username,
		password: password,
		host:     host,
		port:     port,

		stdout: &Writer{},
	}
	err := client.connect()
	if err != nil {
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	return client, nil
}

func NewClientSSHKey(username, password, sshFolderPath, host, port string) (*Client, error) {
	client := &Client{
		username:      username,
		password:      password,
		sshFolderPath: sshFolderPath,
		host:          host,
		port:          port,

		stdout: &Writer{},
	}
	err := client.connect()
	if err != nil {
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	return client, nil
}

func NewClientSSHKeyPem(username, sshKeyPem, host, port string) (*Client, error) {
	client := &Client{
		username:  username,
		sshKeyPem: sshKeyPem,
		host:      host,
		port:      port,

		stdout: &Writer{},
	}
	err := client.connect()
	if err != nil {
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	return client, nil
}

func NewClientPasswordAuth(username, password, host, port string) (*Client, error) {
	client := &Client{
		username: username,
		password: password,
		host:     host,
		port:     port,

		stdout: &Writer{},
	}
	err := client.connectPassword()
	if err != nil {
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	return client, nil
}

func (c *Client) connectPassword() error {
	// SSH client config
	config := &ssh.ClientConfig{
		User: c.username,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to host
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", c.host, c.port), config)
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

func (c *Client) connect() error {
	authMethodList := []ssh.AuthMethod{
		ssh.Password(c.password),
	}

	method, err := c.getAuthMethodPublicKeys()
	if err != nil {
		panic(err)
	} else {
		authMethodList = append([]ssh.AuthMethod{method}, authMethodList...)
	}
	var config *ssh.ClientConfig
	config = &ssh.ClientConfig{
		User: c.username,
		Auth: authMethodList,
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			kh := c.checkKnownHosts()
			hErr := kh(host, remote, pubKey)
			var keyErr *knownhosts.KeyError
			// Reference: https://blog.golang.org/go1.13-errors
			// To understand what errors.As is.
			if errors.As(hErr, &keyErr) && len(keyErr.Want) > 0 {
				// Reference: https://www.godoc.org/golang.org/x/crypto/ssh/knownhosts#KeyError
				// if keyErr.Want slice is empty then host is unknown, if keyErr.Want is not empty
				// and if host is known then there is key mismatch the connection is then rejected.
				log.Printf("WARNING: %v is not a key of %s, either a MiTM attack or %s has reconfigured the host pub key.", string(pubKey.Marshal()), host, host)
				return keyErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) == 0 {
				// host key not found in known_hosts then give a warning and continue to connect.
				log.Printf("WARNING: %s is not trusted, adding this key: %q to known_hosts file.", host, string(pubKey.Marshal()))
				return c.addHostKey(host, remote, pubKey)
			}
			log.Printf("Pub key exists for %s.", host)
			return nil
		}),
	}

	// Connect to host
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", c.host, c.port), config)
	if err != nil {
		return err
	}
	c.client = client
	return nil
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
		ssh.OPOST:         0,
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

func (c *Client) RunYes(cmd string, a ...interface{}) {
	session, err := c.client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		ssh.OPOST:         0,
	}
	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		panic(err)
	}

	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}

	writer := NewYesPromptWriter(in)
	session.Stdout = writer
	session.Stderr = writer

	err = session.Run(fmt.Sprintf(cmd, a...))
	if err != nil {
		panic(err)
	}
}

func (c *Client) RunMultipleCmds(cmds []string, delayDuration time.Duration) {
	session, err := c.client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		ssh.OPOST:         0,
	}
	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		panic(err)
	}
	var stdOut stdOutSingleWriter
	session.Stdout = &stdOut
	session.Stderr = &stdOut

	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}
	err = session.Shell()
	if err != nil {
		panic(err)
	}
	<-time.After(delayDuration)
	for _, cmd := range cmds {
		_, err = in.Write([]byte(cmd + "\n"))
		if err != nil {
			panic(err)
		}
		<-time.After(delayDuration)
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

	var stdoutBuf singleWriter
	session.Stdout = &stdoutBuf
	session.Stderr = &stdoutBuf
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
	return strings.Replace(stdoutBuf.b.String(), "\r", "", -1)
	// return stdoutBuf.String()
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
	cmd := fmt.Sprintf("cat <<'EOF' | sudo tee %s\n%s\nEOF\n", filePath, content)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
}

func (c *Client) WriteToFile(content, filePath string) {
	session := c.createNewSession()
	defer session.Close()
	cmd := fmt.Sprintf("cat <<'EOF' | tee %s\n%s\nEOF\n", filePath, content)
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
}

func (c *Client) WriteToFileExperiment(content, filePath string) {
	session := c.createNewSession()
	defer session.Close()
	cmd := fmt.Sprintf("cat <<'EOF' | tee %s\n%s\nEOF\n", filePath, content)
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

func (c *Client) DownloadFile(remoteFilePath, destFilePath string) {
	session, err := c.client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	out, err := session.StdoutPipe()
	if err != nil {
		panic(err)
	}

	file, err := os.OpenFile(destFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	cmd := fmt.Sprintf("cat %s", remoteFilePath)
	if err := session.Start(cmd); err != nil {
		panic(err)
	}

	_, err = io.Copy(file, out)
	if err != nil {
		panic(err)
	}

	if err := session.Wait(); err != nil {
		panic(err)
	}
}

func (c *Client) UploadFile(sourceFilePath, remoteFilePath string) {
	session, err := c.client.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	remoteDir := fmt.Sprintf("%s/", filepath.Dir(remoteFilePath))
	remoteFileName := strings.TrimPrefix(remoteFilePath, remoteDir)

	file, err := os.Open(sourceFilePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		panic(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		hostIn, err := session.StdinPipe()
		if err != nil {
			panic(err)
		}
		defer hostIn.Close()
		fmt.Fprintf(hostIn, "C0664 %d %s\n", stat.Size(), remoteFileName)

		_, err = io.Copy(hostIn, file)
		if err != nil {
			panic(err)
		}
		fmt.Fprint(hostIn, "\x00")
		wg.Done()
	}()
	cmd := fmt.Sprintf("/usr/bin/scp -t %s", remoteDir)
	err = session.Run(cmd)
	if err != nil {
		panic(err)
	}
	wg.Wait()

}

func (c *Client) Exit() {
	session := c.createNewSession()
	defer session.Close()
	err := session.Run("exit")
	if err != nil {
		panic(err)
	}
	err = c.client.Close()
	if err != nil {
		panic(err)
	}
	removeClientFromLog(c)
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
	client, err := NewClient(username, password, host, port)
	if err != nil {
		panic(err)
	}
	client.Run("mkdir -p ~/.ssh")
	client.AppendToFile(string(pubKeyContent), "~/.ssh/authorized_keys")
	// set permission to rwx for owner only
	client.Run("chmod 700 ~/.ssh")
	client.Run("chmod 700 ~/.ssh/authorized_keys")
	client.Exit()
}
