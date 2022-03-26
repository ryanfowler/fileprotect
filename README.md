# fileprotect

Command line utility to encrypt and decrypt data.

A work in progress!

## Install

```
go install github.com/ryanfowler/fileprotect@latest
```

## Usage

To encrypt a secret, run the command:

```
fileprotect secret encrypt "this is a secret"
```

The `encrypt` command will ask for a password to encrypt the secret with, and
will then output the encrypted result in base64 format.

To decrypt your data, run the command:

```
fileprotect secret decrypt 3vAnXv6kKuA6WVunj6O9zdqhWtgSnzGAbzTL9AHV3nqu0HBPkCE
```

The `decrypt` command will also ask for the password you used to encrypt the
data, and, if successful, output the result.

## How it works

`fileprotect` uses the [argon2id](https://en.wikipedia.org/wiki/Argon2) key
derivation function to hash your password. It takes the resulting 32 byte hash
and uses that as the key to the [chacha20-poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
authenticated encryption algorithm.

Salts are created using a cryptographically secure random number generator. This
means that encrypting the same secret multiple times will result in different
output.
