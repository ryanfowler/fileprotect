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
will then output the encrypted result in hexadecimal format.

To decrypt your data, run the command:

```
fileprotect secret decrypt 2b86dc46601e0046df8bb891f702fa9fd11edc9301e44b51db556671a3803334fb1dcdbe52d256422546ffc6d378ad13696b8c99a4269d8a5aca611f1dd2cc
```

The `decrypt` command will also ask for the password you used to encrypt the
data, and, if successful, output the result.

### How it works

`fileprotect` uses the [argon2id](https://en.wikipedia.org/wiki/Argon2) key
derivation function to hash your password. It takes the resulting 32 byte hash
and uses that as the key to the [xchacha20-poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
authenticated encryption algorithm.
