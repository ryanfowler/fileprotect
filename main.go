package main

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run() error {
	encryptSecretCmd := &ffcli.Command{
		Name:       "encrypt",
		ShortUsage: "fileprotect secret encrypt <secret>",
		ShortHelp:  "Encrypts a secret",
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return errors.New("one argument is required")
			}
			password, err := readPassword()
			if err != nil {
				return err
			}
			out, err := encryptSecret(password, []byte(args[0]))
			if err != nil {
				return err
			}
			_, err = io.WriteString(os.Stdout, out)
			return err
		},
	}
	decryptSecretCmd := &ffcli.Command{
		Name:       "decrypt",
		ShortUsage: "fileprotect secret decrypt <secret>",
		ShortHelp:  "Decrypts a secret that was previously encrypted",
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 1 {
				return errors.New("one argument is required")
			}
			password, err := readPassword()
			if err != nil {
				return err
			}
			out, err := decryptSecret(password, args[0])
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(out)
			return err
		},
	}

	secretCmd := &ffcli.Command{
		Name:        "secret",
		ShortHelp:   "Encrypt and decrypt secrets",
		Subcommands: []*ffcli.Command{encryptSecretCmd, decryptSecretCmd},
	}

	root := &ffcli.Command{
		Name:        "fileprotect",
		LongHelp:    "Command line tool for encrypting/decrypting data.",
		Subcommands: []*ffcli.Command{secretCmd},
	}
	return root.ParseAndRun(context.Background(), os.Args[1:])
}

func readPassword() ([]byte, error) {
	_, err := io.WriteString(os.Stderr, "Password: ")
	if err != nil {
		return nil, err
	}
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	return password, nil
}

var zeroNonce [chacha20poly1305.NonceSize]byte

func encryptSecret(password, plaintext []byte) (string, error) {
	var passSalt [16]byte
	if _, err := io.ReadFull(rand.Reader, passSalt[:]); err != nil {
		return "", err
	}

	aead, err := newAEAD(password, passSalt[:])
	if err != nil {
		return "", err
	}

	ciphertext := aead.Seal(passSalt[:], zeroNonce[:], plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptSecret(password []byte, ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < 16 {
		return nil, errors.New("invalid ciphertext")
	}

	passSalt := ciphertext[:16]
	aead, err := newAEAD(password, passSalt)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, zeroNonce[:], ciphertext[16:], nil)
}

func newAEAD(password, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey(password, salt, 8, 256*1024, 4, chacha20poly1305.KeySize)
	return chacha20poly1305.New(key)
}
