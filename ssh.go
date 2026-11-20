package sshclient

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

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

	// local is set when the host is 127.0.0.1/localhost: commands run with os/exec instead of ssh
	local        bool
	localHomeDir string

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
	err := client.connectOrLocal(client.connect)
	if err != nil {
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	return client, nil
}

func NewClientSSHKey(username, password, sshFolderPath, host, port string) (*Client, error) {
	start := time.Now()
	sshPrint("NewClientSSHKey start")
	client := &Client{
		username:      username,
		password:      password,
		sshFolderPath: sshFolderPath,
		host:          host,
		port:          port,

		stdout: &Writer{},
	}
	err := client.connectOrLocal(client.connect)
	if err != nil {
		sshPrint(fmt.Sprintf("NewClientSSHKey error took %s", time.Since(start)))
		return nil, err
	}
	client.stackLog = GetStack()
	addClientToLog(client)
	sshPrint(fmt.Sprintf("NewClientSSHKey done took %s", time.Since(start)))
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
	err := client.connectOrLocal(client.connect)
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
	err := client.connectOrLocal(client.connectPassword)
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
	start := time.Now()
	sshPrint("connect start")
	authMethodList := []ssh.AuthMethod{
		ssh.Password(c.password),
	}

	authStart := time.Now()
	sshPrint("getAuthMethodPublicKeys start")
	method, err := c.getAuthMethodPublicKeys()
	if err != nil {
		panic(err)
	} else {
		authMethodList = append([]ssh.AuthMethod{method}, authMethodList...)
	}
	sshPrint(fmt.Sprintf("getAuthMethodPublicKeys done took %s", time.Since(authStart)))
	addr := fmt.Sprintf("%s:%s", c.host, c.port)
	algoStart := time.Now()
	sshPrint("hostKeyAlgorithms start")
	algos := c.hostKeyAlgorithms(addr)
	sshPrint(fmt.Sprintf("hostKeyAlgorithms done took %s", time.Since(algoStart)))
	config := &ssh.ClientConfig{
		User:              c.username,
		Auth:              authMethodList,
		HostKeyCallback:   c.hostKeyCallback,
		HostKeyAlgorithms: algos,
	}

	dialStart := time.Now()
	sshPrint("ssh.Dial start")
	client, err := ssh.Dial("tcp", addr, config)
	sshPrint(fmt.Sprintf("ssh.Dial done took %s", time.Since(dialStart)))
	if err != nil {
		sshPrint(fmt.Sprintf("connect error took %s", time.Since(start)))
		return err
	}
	c.client = client
	sshPrint(fmt.Sprintf("connect done took %s", time.Since(start)))
	return nil
}

func (c *Client) createNewSession() cmdSession {
	return c.createNewSessionCapture(nil, sshCaller(2))
}

// createNewSessionCapture is createNewSession with an optional writer that
// receives a copy of the session output (stdout+stderr, merged by the pty)
func (c *Client) createNewSessionCapture(capture io.Writer, caller string) cmdSession {
	start := time.Now()
	sshPrint(fmt.Sprintf("createNewSession start caller=%s", caller))
	sessionStart := time.Now()
	sshPrint("NewSession start")
	session, err := c.newSession()
	sshPrint(fmt.Sprintf("NewSession done took %s", time.Since(sessionStart)))
	if err != nil {
		panic(err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		ssh.OPOST:         0,
	}
	ptyStart := time.Now()
	sshPrint("RequestPty start")
	err = session.RequestPty("xterm", 80, 40, modes)
	sshPrint(fmt.Sprintf("RequestPty done took %s", time.Since(ptyStart)))
	if err != nil {
		panic(err)
	}

	pipeStart := time.Now()
	sshPrint("StdinPipe start")
	in, err := session.StdinPipe()
	sshPrint(fmt.Sprintf("StdinPipe done took %s", time.Since(pipeStart)))
	if err != nil {
		panic(err)
	}

	writer := NewPasswordPromptWriter(in, c.username, c.password)
	writer.capture = capture
	session.SetStdout(writer)
	session.SetStderr(writer)

	sshPrint(fmt.Sprintf("createNewSession done took %s", time.Since(start)))
	return session
}

// maxRunErrorOutput caps how much captured output is attached to a run error
// so a panic message (which may be forwarded to telegram) stays readable
const maxRunErrorOutput = 2000

// runError wraps a session error with the command and the output it produced,
// so a panic shows e.g. "Process exited with status 127 ... zsh:1: command not found: zip"
// instead of only the exit status
func runError(err error, cmd string, output *singleWriter) error {
	out := strings.TrimSpace(strings.ReplaceAll(output.String(), "\r", ""))
	if len(out) > maxRunErrorOutput {
		out = "..." + out[len(out)-maxRunErrorOutput:]
	}
	if out == "" {
		return fmt.Errorf("%w\ncmd: %s", err, cmd)
	}
	return fmt.Errorf("%w\ncmd: %s\noutput: %s", err, cmd, out)
}

// Run runs fmt.Sprintf(cmd, a...) in the remote shell. Wrap every non-constant value in Quote.
func (c *Client) Run(cmd string, a ...interface{}) {
	start := time.Now()
	fullCmd := fmt.Sprintf(cmd, a...)
	sshPrint(fmt.Sprintf("Run start cmd=%s", fullCmd))
	var output singleWriter
	session := c.createNewSessionCapture(&output, "Run")
	defer session.Close()
	runStart := time.Now()
	sshPrint("Run session.Run start")
	err := session.Run(fullCmd)
	sshPrint(fmt.Sprintf("Run session.Run done took %s", time.Since(runStart)))
	if err != nil {
		panic(runError(err, fullCmd, &output))
	}
	sshPrint(fmt.Sprintf("Run done took %s", time.Since(start)))
}

func (c *Client) RunYes(cmd string, a ...interface{}) {
	session, err := c.newSession()
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
	session.SetStdout(writer)
	session.SetStderr(writer)

	err = session.Run(fmt.Sprintf(cmd, a...))
	if err != nil {
		panic(err)
	}
}

func (c *Client) RunMultipleCmds(cmds []string, delayDuration time.Duration) {
	session, err := c.newSession()
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
	session.SetStdout(&stdOut)
	session.SetStderr(&stdOut)

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

// Output runs cmd in the remote shell. Wrap every non-constant value in Quote.
func (c *Client) Output(cmd string) string {
	start := time.Now()
	sshPrint(fmt.Sprintf("Output start cmd=%s", cmd))
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf singleWriter
	session.SetStdout(&stdoutBuf)
	session.SetStderr(&stdoutBuf)
	runStart := time.Now()
	sshPrint("session.Run start")
	err := session.Run(cmd)
	sshPrint(fmt.Sprintf("session.Run done took %s", time.Since(runStart)))
	if err != nil {
		panic(runError(err, cmd, &stdoutBuf))
	}
	sshPrint(fmt.Sprintf("Output done took %s", time.Since(start)))
	return strings.Replace(stdoutBuf.b.String(), "\r", "", -1)
	// return stdoutBuf.String()
}

func (c *Client) OutputIgnoreError(cmd string) string {
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.SetStdout(&stdoutBuf)
	if c.local {
		// over ssh the pty merges stderr into stdout; do the same locally so callers see identical output
		session.SetStderr(&stdoutBuf)
	}
	session.Run(cmd)
	return stdoutBuf.String()
}

func (c *Client) SUDORun(cmd string, a ...interface{}) {
	start := time.Now()
	fullCmd := fmt.Sprintf("%s %s", c.sudo(), fmt.Sprintf(cmd, a...))
	sshPrint(fmt.Sprintf("SUDORun start cmd=%s", fullCmd))
	var output singleWriter
	session := c.createNewSessionCapture(&output, "SUDORun")
	defer session.Close()
	runStart := time.Now()
	sshPrint("SUDORun session.Run start")
	err := session.Run(fullCmd)
	sshPrint(fmt.Sprintf("SUDORun session.Run done took %s", time.Since(runStart)))
	if err != nil {
		panic(runError(err, fullCmd, &output))
	}
	sshPrint(fmt.Sprintf("SUDORun done took %s", time.Since(start)))
}

// SUDOWriteToFile writes content plus a trailing newline as root.
// Without a sudo password, `sudo -n` never prompts, so content streams over stdin like WriteToFile.
// With a password, sudo prompts on the pty, which would mangle stdin data, so the content travels
// base64-encoded inside the command instead. That path is capped by the remote argument size limit
// (128KB per argument on Linux), the same cap the old heredoc had.
func (c *Client) SUDOWriteToFile(content, filePath string) {
	content += "\n"
	if c.sudo() == "sudo -n" {
		c.teeFromStdin("SUDOWriteToFile", "sudo -n tee "+QuotePath(filePath), content)
		return
	}

	start := time.Now()
	sshPrint(fmt.Sprintf("SUDOWriteToFile start path=%s size=%d", filePath, len(content)))
	var output singleWriter
	session := c.createNewSessionCapture(&output, "SUDOWriteToFile")
	defer session.Close()
	teeCmd := fmt.Sprintf("%s tee %s", c.sudo(), QuotePath(filePath))
	cmd := fmt.Sprintf("printf '%%s' %s | base64 -d | %s > /dev/null",
		Quote(base64.StdEncoding.EncodeToString([]byte(content))), teeCmd)
	err := session.Run(cmd)
	if err != nil {
		// report teeCmd, not cmd: cmd carries the content (e.g. an ssl key)
		panic(runError(err, teeCmd, &output))
	}
	sshPrint(fmt.Sprintf("SUDOWriteToFile done took %s", time.Since(start)))
}

// WriteToFile writes content plus a trailing newline, the same bytes the old heredoc version wrote.
func (c *Client) WriteToFile(content, filePath string) {
	c.teeFromStdin("WriteToFile", "tee "+QuotePath(filePath), content+"\n")
}

func (c *Client) WriteToFileExperiment(content, filePath string) {
	c.WriteToFile(content, filePath)
}

func (c *Client) AppendToFile(content, filePath string) {
	c.teeFromStdin("AppendToFile", "tee -a "+QuotePath(filePath), content+"\n")
}

// teeFromStdin streams content to the remote command's stdin instead of embedding it in the command,
// so no content (a line "EOF", a quote, `$(...)`) can end the data and run as a shell command.
// The session has no pty on purpose: a pty's line discipline would rewrite the bytes and cap line length.
func (c *Client) teeFromStdin(caller, teeCmd, content string) {
	start := time.Now()
	sshPrint(fmt.Sprintf("%s start cmd=%s size=%d", caller, teeCmd, len(content)))
	session, err := c.newSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	var output singleWriter
	session.SetStdout(&output)
	session.SetStderr(&output)
	in, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}

	cmd := teeCmd + " > /dev/null"
	err = session.Start(cmd)
	if err != nil {
		panic(runError(err, cmd, &output))
	}
	_, writeErr := io.WriteString(in, content)
	closeErr := in.Close()
	waitErr := session.Wait()
	for _, err := range []error{waitErr, writeErr, closeErr} {
		if err != nil {
			panic(runError(err, cmd, &output))
		}
	}
	sshPrint(fmt.Sprintf("%s done took %s", caller, time.Since(start)))
}

// Quote returns s as one single-quoted shell word. Use it for every value put into a command
// passed to Run, SUDORun, Output, OutputIgnoreError or StreamOutput: those run their string in a shell.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// QuotePath is Quote that keeps a leading ~/ outside the quotes, so home-relative paths still expand.
func QuotePath(path string) string {
	if strings.HasPrefix(path, "~/") {
		return "~/" + Quote(path[2:])
	}
	return Quote(path)
}

func (c *Client) IsFileExist(filePath string) bool {
	session := c.createNewSession()
	defer session.Close()

	var stdoutBuf bytes.Buffer
	session.SetStdout(&stdoutBuf)

	cmd := fmt.Sprintf("(ls %s >> /dev/null 2>&1 && echo true) || echo false", QuotePath(filePath))
	err := session.Run(cmd)
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(stdoutBuf.String()) == "true"
}

func (c *Client) DownloadFile(remoteFilePath, destFilePath string) {
	session, err := c.newSession()
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
	cmd := fmt.Sprintf("cat %s", QuotePath(remoteFilePath))
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
	start := time.Now()
	sshPrint(fmt.Sprintf("UploadFile start %s -> %s", sourceFilePath, remoteFilePath))
	if c.local {
		err := c.localCopyFile(sourceFilePath, remoteFilePath)
		if err != nil {
			panic(wrapUploadErr(sourceFilePath, remoteFilePath, err, ""))
		}
		sshPrint(fmt.Sprintf("UploadFile local done took %s", time.Since(start)))
		return
	}
	session, err := c.newSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	remoteDir := fmt.Sprintf("%s/", filepath.Dir(remoteFilePath))
	remoteFileName := filepath.Base(remoteFilePath)

	file, err := os.Open(sourceFilePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		panic(err)
	}

	hostIn, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}

	var stderrBuf bytes.Buffer
	session.SetStderr(&stderrBuf)

	cmd := fmt.Sprintf("/usr/bin/scp -t %s", QuotePath(remoteDir))
	runStart := time.Now()
	sshPrint("UploadFile scp start")
	err = session.Start(cmd)
	if err != nil {
		panic(wrapUploadErr(sourceFilePath, remoteFilePath, err, stderrBuf.String()))
	}

	_, err = fmt.Fprintf(hostIn, "C0664 %d %s\n", stat.Size(), remoteFileName)
	if err != nil {
		hostIn.Close()
		waitErr := session.Wait()
		panic(wrapUploadErr(sourceFilePath, remoteFilePath, firstErr(err, waitErr), stderrBuf.String()))
	}
	_, err = io.CopyN(hostIn, file, stat.Size())
	if err != nil {
		hostIn.Close()
		waitErr := session.Wait()
		panic(wrapUploadErr(sourceFilePath, remoteFilePath, firstErr(err, waitErr), stderrBuf.String()))
	}
	_, err = fmt.Fprint(hostIn, "\x00")
	if err != nil {
		hostIn.Close()
		waitErr := session.Wait()
		panic(wrapUploadErr(sourceFilePath, remoteFilePath, firstErr(err, waitErr), stderrBuf.String()))
	}
	hostIn.Close()

	err = session.Wait()
	sshPrint(fmt.Sprintf("UploadFile scp done took %s", time.Since(runStart)))
	if err != nil {
		panic(wrapUploadErr(sourceFilePath, remoteFilePath, err, stderrBuf.String()))
	}
	sshPrint(fmt.Sprintf("UploadFile done took %s", time.Since(start)))
}

func firstErr(errList ...error) error {
	for _, err := range errList {
		if err != nil && err != io.EOF {
			return err
		}
	}
	for _, err := range errList {
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("upload failed")
}

func wrapUploadErr(sourceFilePath, remoteFilePath string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr != "" {
		return fmt.Errorf("upload %s -> %s: %v: %s", sourceFilePath, remoteFilePath, err, stderr)
	}
	return fmt.Errorf("upload %s -> %s: %v", sourceFilePath, remoteFilePath, err)
}

func (c *Client) WriteBigFile(content string, remoteFilePath string) {
	randFileName := RandSeq(15)
	tempFilePath := fmt.Sprintf("/tmp/%v.tmp", randFileName)
	err := ioutil.WriteFile(tempFilePath, []byte(content), 0777)
	if err != nil {
		panic(err)
	}
	c.UploadFile(tempFilePath, remoteFilePath)
	err = os.Remove(tempFilePath)
	if err != nil {
		panic(err)
	}
}

func (c *Client) SUDOWriteBigFile(content string, remoteFilePath string) {
	start := time.Now()
	sshPrint(fmt.Sprintf("SUDOWriteBigFile start path=%s size=%d", remoteFilePath, len(content)))
	randFileName := RandSeq(15)
	tempFilePath := fmt.Sprintf("/tmp/%v.tmp", randFileName)
	err := ioutil.WriteFile(tempFilePath, []byte(content), 0777)
	if err != nil {
		panic(err)
	}
	randFileNameDest := RandSeq(15)
	tempFilePathDest := fmt.Sprintf("/tmp/%v.tmp", randFileNameDest)
	c.UploadFile(tempFilePath, tempFilePathDest)
	c.SUDORun("mv %s %s", Quote(tempFilePathDest), QuotePath(remoteFilePath))
	sshPrint(fmt.Sprintf("SUDOWriteBigFile done took %s", time.Since(start)))
}

func (c *Client) Exit() {
	start := time.Now()
	sshPrint("Exit start")
	if c.local {
		// nothing to close for local exec
		removeClientFromLog(c)
		sshPrint(fmt.Sprintf("Exit local done took %s", time.Since(start)))
		return
	}
	session := c.createNewSession()
	defer session.Close()
	runStart := time.Now()
	sshPrint("Exit session.Run start")
	err := session.Run("exit")
	sshPrint(fmt.Sprintf("Exit session.Run done took %s", time.Since(runStart)))
	if err != nil {
		panic(err)
	}
	closeStart := time.Now()
	sshPrint("client.Close start")
	err = c.client.Close()
	sshPrint(fmt.Sprintf("client.Close done took %s", time.Since(closeStart)))
	if err != nil {
		panic(err)
	}
	removeClientFromLog(c)
	sshPrint(fmt.Sprintf("Exit done took %s", time.Since(start)))
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
