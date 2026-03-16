package gpg

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// ExecClient decrypts GPG ciphertext by invoking the system gpg binary.
// The GPG keyring must already have the appropriate private key imported.
// No Go crypto dependencies are required.
type ExecClient struct {
	gpgBin string // path to gpg binary, defaults to "gpg"
}

// ExecOption configures an ExecClient.
type ExecOption func(*ExecClient)

// WithGPGBinary sets the path to the gpg binary.
// Defaults to "gpg" (resolved via PATH).
func WithGPGBinary(path string) ExecOption {
	return func(c *ExecClient) {
		c.gpgBin = path
	}
}

// NewExecClient creates an ExecClient that delegates to the system gpg binary.
// The calling process must have a GPG keyring with the appropriate private key
// already imported and (if passphrase-protected) accessible via gpg-agent.
func NewExecClient(opts ...ExecOption) *ExecClient {
	c := &ExecClient{gpgBin: "gpg"}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Decrypt decrypts the GPG-encrypted ciphertext using the system gpg binary.
// It accepts both ASCII-armored and binary OpenPGP messages.
// The private key must be available in the system GPG keyring.
func (c *ExecClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.gpgBin,
		"--batch",
		"--quiet",
		"--decrypt",
		"--output", "-",
	)
	cmd.Stdin = bytes.NewReader(ciphertext)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg exec: %w: %s", err, stderr.String())
	}

	plaintext := make([]byte, stdout.Len())
	copy(plaintext, stdout.Bytes())
	return plaintext, nil
}

// Compile-time interface check.
var _ Client = (*ExecClient)(nil)
