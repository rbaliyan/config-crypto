package gpg

import (
	"context"
	"os/exec"
	"testing"
)

func TestNewExecClientDefaults(t *testing.T) {
	c := NewExecClient()
	if c.gpgBin != "gpg" {
		t.Errorf("default gpgBin: got %q, want %q", c.gpgBin, "gpg")
	}
}

func TestWithGPGBinary(t *testing.T) {
	c := NewExecClient(WithGPGBinary("/usr/local/bin/gpg2"))
	if c.gpgBin != "/usr/local/bin/gpg2" {
		t.Errorf("gpgBin: got %q, want %q", c.gpgBin, "/usr/local/bin/gpg2")
	}
}

func TestExecClientDecryptBinaryNotFound(t *testing.T) {
	c := NewExecClient(WithGPGBinary("/nonexistent/gpg"))

	_, err := c.Decrypt(context.Background(), []byte("anything"))
	if err == nil {
		t.Error("expected error when gpg binary does not exist")
	}
}

func TestExecClientDecryptBadCiphertext(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg binary not found in PATH")
	}

	c := NewExecClient()
	_, err := c.Decrypt(context.Background(), []byte("this is not valid gpg data"))
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

func TestExecClientDecryptContextCancelled(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg binary not found in PATH")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewExecClient()
	_, err := c.Decrypt(ctx, []byte("some data"))
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}
