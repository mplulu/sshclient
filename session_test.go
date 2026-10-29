package sshclient

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newLocalTestClient(t *testing.T) *Client {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// the ssh folder has no key: a local client must never try to dial
	client, err := NewClientSSHKey(current.Username, "", t.TempDir(), "127.0.0.1", "22")
	if err != nil {
		t.Fatal(err)
	}
	if !client.local {
		t.Fatal("expected local exec client")
	}
	t.Cleanup(client.Exit)
	return client
}

func expectPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}

func TestIsLocalHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", " 127.0.0.1 "} {
		if !isLocalHost(host) {
			t.Errorf("%q should be local", host)
		}
	}
	for _, host := range []string{"10.0.0.1", "127.0.0.2", "example.com", ""} {
		if isLocalHost(host) {
			t.Errorf("%q should not be local", host)
		}
	}
}

func TestLocalUserMismatch(t *testing.T) {
	_, err := NewClientSSHKey("sshclient-no-such-user", "", t.TempDir(), "localhost", "22")
	if err == nil || !strings.Contains(err.Error(), "SetForceSSH") {
		t.Fatalf("expected user mismatch error, got %v", err)
	}
}

func TestLocalOutput(t *testing.T) {
	client := newLocalTestClient(t)
	got := client.Output("echo out; echo err 1>&2")
	if got != "out\nerr\n" {
		t.Fatalf("got %q", got)
	}
	if got := client.OutputIgnoreError("echo out; cat /sshclient-missing-file; exit 3"); !strings.HasPrefix(got, "out\n") || !strings.Contains(got, "sshclient-missing-file") {
		t.Fatalf("got %q", got)
	}
	expectPanic(t, func() { client.Run("exit 1") })
}

func TestLocalEnvLikeLogin(t *testing.T) {
	client := newLocalTestClient(t)
	got := strings.Split(strings.TrimSpace(client.Output(`pwd; echo "$HOME"; echo "$USER"; echo "$PATH"`)), "\n")
	if len(got) != 4 {
		t.Fatalf("got %q", got)
	}
	home, err := filepath.EvalSymlinks(client.localHomeDir)
	if err != nil {
		t.Fatal(err)
	}
	pwd, _ := filepath.EvalSymlinks(got[0])
	if pwd != home || got[1] != client.localHomeDir || got[2] != client.username {
		t.Fatalf("got %q", got)
	}
	if !strings.HasPrefix(got[3], localBasePath) {
		t.Fatalf("PATH %q misses sbin folders", got[3])
	}
}

func TestLocalFiles(t *testing.T) {
	client := newLocalTestClient(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "a.conf")
	content := "server {\n\tlisten 80; # $not_expanded `nor this`\n}"

	if client.IsFileExist(path) {
		t.Fatal("file should not exist yet")
	}
	client.WriteToFile(content, path)
	if !client.IsFileExist(path) {
		t.Fatal("file should exist")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != content+"\n" {
		t.Fatalf("got %q", data)
	}

	big := strings.Repeat("0123456789", 100000)
	bigPath := filepath.Join(dir, "big.html")
	client.WriteBigFile(big, bigPath)
	data, err = os.ReadFile(bigPath)
	if err != nil || string(data) != big {
		t.Fatalf("big file mismatch err=%v len=%d", err, len(data))
	}

	downloadPath := filepath.Join(dir, "download.conf")
	client.DownloadFile(path, downloadPath)
	data, err = os.ReadFile(downloadPath)
	if err != nil || string(data) != content+"\n" {
		t.Fatalf("download mismatch err=%v data=%q", err, data)
	}

	expectPanic(t, func() { client.UploadFile(path, filepath.Join(dir, "missing", "x")) })
}

func TestLocalStreamOutput(t *testing.T) {
	client := newLocalTestClient(t)
	var sb strings.Builder
	timeout := time.After(10 * time.Second)
	ch := client.StreamOutput("echo a; echo b")
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				if sb.String() != "a\nb\n" {
					t.Fatalf("got %q", sb.String())
				}
				return
			}
			sb.Write(b)
		case <-timeout:
			t.Fatal("stream did not finish")
		}
	}
}

func TestSudoPrefix(t *testing.T) {
	if got := (&Client{local: true, password: "x"}).sudo(); got != "sudo -n" {
		t.Errorf("local got %q", got)
	}
	if got := (&Client{}).sudo(); got != "sudo -n" {
		t.Errorf("no password got %q", got)
	}
	if got := (&Client{password: "x"}).sudo(); got != "sudo" {
		t.Errorf("password got %q", got)
	}
}
