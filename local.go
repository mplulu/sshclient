package sshclient

import (
	"fmt"
	"os/exec"
)

type ClientLocal struct {
}

func NewClientLoca1l() *ClientLocal {
	c := &ClientLocal{}
	return c
}

func (c *ClientLocal) PromptPassword(password, name string, a ...string) {
	cmd := exec.Command("pwd")
	fmt.Println(name, a)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}
	writer := NewPasswordPromptWriter(stdinPipe, "", password)
	cmd.Stdout = writer
	cmd.Stderr = writer
	err = cmd.Run()
	if err != nil {
		panic(err)
	}
}
