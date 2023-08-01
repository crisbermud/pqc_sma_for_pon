use std::collections::HashSet;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use rand::RngCore;

use crate::utils::sha256;

use super::CryptoCapability;
use super::CryptoContext;
use super::OLT;
use super::ONU;

pub trait Inner: Default {}

#[derive(Default)]
pub struct InnerONU;
impl Inner for InnerONU {}
#[derive(Default)]
pub struct InnerOLT;

impl Inner for InnerOLT {}

pub struct Common<I: Inner> {
    secret: Option<x25519_dalek::ReusableSecret>,
    signing_key: Option<ed25519_dalek::SigningKey>,
    their_pubkey: Option<ed25519_dalek::VerifyingKey>,
    shared_secret: Vec<u8>,
    _inner: I,
}

impl<I: Inner> Default for Common<I> {
    fn default() -> Self {
        Self {
            secret: None,
            signing_key: None,
            their_pubkey: None,
            _inner: Default::default(),
            shared_secret: Vec::new(),
        }
    }
}

impl<T: Inner> Common<T> {
    pub fn gen_keypair(&mut self) {
        let mut key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut key);
        self.signing_key = Some(SigningKey::from_bytes(&key));
    }

    pub fn set_other_pubkey(&mut self, key: ed25519_dalek::VerifyingKey) {
        self.their_pubkey = Some(key);
    }

    pub fn get_pubkey(&self) -> ed25519_dalek::VerifyingKey {
        return self.signing_key.as_ref().unwrap().verifying_key();
    }

    fn gen_challenge(&mut self) -> Vec<u8> {
        let mut msg = x25519_dalek::PublicKey::from(self.secret.as_ref().unwrap())
            .to_bytes()
            .to_vec();
        msg.extend(self.signing_key.as_ref().unwrap().sign(&msg).to_bytes());
        return msg;
    }

    fn calculate_shared(&mut self, msg: &[u8]) {
        assert!(msg.len() > 32);
        self.their_pubkey
            .unwrap()
            .verify(
                &msg[..32],
                &ed25519_dalek::Signature::from_bytes((&msg[32..]).try_into().unwrap()),
            )
            .unwrap();
        let only_msg: [u8; 32] = msg[..32].try_into().unwrap();
        self.shared_secret = self
            .secret
            .as_ref()
            .unwrap()
            .diffie_hellman(&x25519_dalek::PublicKey::from(only_msg))
            .as_bytes()
            .to_vec();
    }
}

pub type ONU25519 = Common<InnerONU>;

impl ONU for ONU25519 {
    fn set_olt_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps.iter().next().expect("assertion above"),
            &CryptoCapability::DHE_ED25519,
        );
    }

    fn set_olt_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        self.secret = Some(x25519_dalek::ReusableSecret::random_from_rng(&mut ctx.rng));
        self.calculate_shared(&data);
    }

    fn set_olt_challenge_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }

    fn get_onu_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        self.gen_challenge()
    }

    fn get_onu_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        vec![]
    }

    fn get_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
    ) -> HashSet<CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(CryptoCapability::DHE_ED25519);
        return ret;
    }

    fn set_olt_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        // ignore
    }

    fn set_olt_result_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }

    fn get_onu_authentication_state(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }

    fn get_master_session_key_name(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        sha256(&self.shared_secret)
    }
}

pub type OLT25519 = Common<InnerOLT>;
impl OLT for OLT25519 {
    fn get_olt_crypto_capabilites(&mut self, ctx: &mut CryptoContext) -> HashSet<CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(CryptoCapability::DHE_ED25519);
        return ret;
    }

    fn get_olt_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        self.secret = Some(x25519_dalek::ReusableSecret::random_from_rng(&mut ctx.rng));
        self.gen_challenge()
    }

    fn get_olt_challenge_status(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }

    fn set_onu_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        self.calculate_shared(&data);
    }

    fn set_onu_authentication_result(&mut self, ctx: &mut CryptoContext, _data: Vec<u8>) {
        // Ignore
    }

    fn set_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps.iter().next().expect("assertion above"),
            &CryptoCapability::DHE_ED25519,
        );
    }

    fn get_olt_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        vec![]
    }

    fn get_olt_result_status(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }

    fn set_onu_authentication_state(&mut self, ctx: &mut CryptoContext, state: bool) {
        assert!(state);
    }

    fn set_master_session_key_name(&mut self, ctx: &mut CryptoContext, msk_name: Vec<u8>) {
        let ours = sha256(&self.shared_secret);
        assert_eq!(ours, msk_name);
    }
}
