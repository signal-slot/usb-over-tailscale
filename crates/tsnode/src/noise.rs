//! Noise protocol symmetric state (BLAKE2s / ChaChaPoly / X25519), shared by the
//! ts2021 control handshake (`Noise_IK`) and WireGuard (`Noise_IKpsk2`).

use crate::crypto::{aead_decrypt, aead_encrypt, blake2s, hkdf, x25519, CryptoError};

#[derive(Clone)]
pub struct SymmetricState {
    pub h: [u8; 32],
    pub ck: [u8; 32],
    k: Option<[u8; 32]>,
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            blake2s(&[protocol_name])
        };
        SymmetricState { h, ck: h, k: None }
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake2s(&[&self.h, data]);
    }

    pub fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k, _) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(k);
    }

    /// `MixKeyAndHash` from the Noise spec, used for WireGuard's psk.
    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let (ck, temp_h, k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.mix_hash(&temp_h);
        self.k = Some(k);
    }

    pub fn mix_dh(&mut self, secret: &[u8; 32], public: &[u8; 32]) {
        self.mix_key(&x25519(secret, public));
    }

    /// Encrypts with the current key (nonce 0, since every key is used once
    /// during a handshake) and mixes the ciphertext into the hash.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let k = self.k.expect("encrypt_and_hash before mix_key");
        let ct = aead_encrypt(&k, 0, plaintext, &self.h);
        self.mix_hash(&ct);
        ct
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let k = self.k.expect("decrypt_and_hash before mix_key");
        let pt = aead_decrypt(&k, 0, ciphertext, &self.h)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    /// Final `Split`: returns (initiator->responder key, responder->initiator key).
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let (k1, k2, _) = hkdf(&self.ck, &[]);
        (k1, k2)
    }
}
