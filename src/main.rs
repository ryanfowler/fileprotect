use std::io::{self, Read, Write};

use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    Algorithm, Argon2, Params, Version,
};
use base64::{decode, encode};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rpassword::prompt_password;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "fileprotect", about = "Encrypt and decrypt sensitive data")]
enum Fileprotect {
    Decrypt,
    Encrypt,
}

fn main() {
    let opt = Fileprotect::from_args();

    let mut input_raw = Vec::new();
    io::stdin().read_to_end(&mut input_raw).unwrap();
    let input = String::from_utf8(input_raw).unwrap();

    let password = prompt_password("Password: ").unwrap();

    match opt {
        Fileprotect::Decrypt => {
            let ciphertext = decode(input.trim()).unwrap();
            let salt = &ciphertext[..16];
            let aead = new_aead(password.as_bytes(), &salt);
            let nonce = Nonce::default();
            let plaintext = aead.decrypt(&nonce, &ciphertext[16..]).unwrap();
            io::stdout().write(&plaintext).unwrap();
        }
        Fileprotect::Encrypt => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let aead = new_aead(password.as_bytes(), &salt);
            let nonce = Nonce::default();
            let ct = aead.encrypt(&nonce, input.trim().as_bytes()).unwrap();
            let out = [&salt, ct.as_slice()].concat();
            io::stdout().write(encode(out).as_bytes()).unwrap();
        }
    }
}

fn new_aead(password: &[u8], salt: &[u8]) -> ChaCha20Poly1305 {
    let params = Params::new(256 * 1024, 8, 4, Some(32)).unwrap();
    let ph = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut raw_key = [0u8; 32];
    ph.hash_password_into(password, salt, &mut raw_key).unwrap();

    let key = Key::from_slice(&raw_key);
    ChaCha20Poly1305::new(key)
}
