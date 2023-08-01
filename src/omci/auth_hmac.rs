use std::collections::HashSet;

use super::OLT;
use super::ONU;
use super::{CryptoCapability, CryptoContext};
use hmac::{Mac, SimpleHmac};
use rand::RngCore;
use sha2::Sha256;

#[derive(Default)]
pub struct AuthFunctionHMAC256 {
    onu_challenge: Option<Vec<u8>>,
    olt_challenge: Option<Vec<u8>>,
    psk: Option<Vec<u8>>,
    onu_serial: Option<Vec<u8>>,
}

impl AuthFunctionHMAC256 {
    fn calc_concat_hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut input = Vec::<u8>::new();
        for &part in parts {
            input.extend(part);
        }
        let mut mac = SimpleHmac::<Sha256>::new_from_slice(self.psk.as_ref().unwrap())
            .expect("HMAC can take any key size");
        mac.update(&input);
        let bytes = mac.finalize().into_bytes();
        return Vec::from(&*bytes);
    }

    pub fn set_psk(&mut self, psk: &[u8]) {
        self.psk = Some(Vec::from(psk));
    }
}

/// seperate implementation of actual hashing that could be adapted or abstracted to other hash functions
impl AuthFunctionHMAC256 {
    fn crypto_capability() -> CryptoCapability {
        return CryptoCapability::HMAC_SHA_256;
    }

    fn set_onu_challenge(&mut self, challenge: &[u8]) {
        self.onu_challenge = Some(Vec::from(challenge));
    }

    fn set_olt_challenge(&mut self, challenge: &[u8]) {
        self.olt_challenge = Some(Vec::from(challenge));
    }

    fn set_onu_serial(&mut self, serial: &[u8]) {
        self.onu_serial = Some(Vec::from(serial));
    }

    fn calc_onu_result(&self) -> Vec<u8> {
        self.calc_concat_hash(&[
            self.olt_challenge.as_ref().unwrap(),
            self.onu_challenge.as_ref().unwrap(),
            &[0; 8],
        ])
    }

    fn calc_olt_result(&self) -> Vec<u8> {
        self.calc_concat_hash(&[
            self.olt_challenge.as_ref().unwrap(),
            self.onu_challenge.as_ref().unwrap(),
            self.onu_serial.as_ref().unwrap(),
        ])
    }

    fn calc_msk(&self) -> Vec<u8> {
        self.calc_concat_hash(&[
            self.olt_challenge.as_ref().unwrap(),
            self.onu_challenge.as_ref().unwrap(),
        ])
    }

    fn calc_msk_name(&self) -> Vec<u8> {
        let mut ret = self.calc_concat_hash(&[
            self.olt_challenge.as_ref().unwrap(),
            self.onu_challenge.as_ref().unwrap(),
            &[
                0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x31, 0x41, 0x59, 0x26, 0x53, 0x58,
                0x97, 0x93,
            ],
        ]);
        ret.truncate(128 / 8);
        return ret;
    }
}

#[derive(Default)]
pub struct ONUHMAC {
    auth: AuthFunctionHMAC256,
    crypto: CryptoCapability,
    authentication_state: bool,
}

impl ONUHMAC {
    pub fn new(serial: &[u8], psk: &[u8]) -> Self {
        assert_eq!(serial.len(), 8);
        let mut ret = Self::default();
        ret.auth.set_onu_serial(serial);
        ret.auth.set_psk(psk);
        return ret;
    }
}

impl ONU for ONUHMAC {
    fn set_olt_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        self.crypto = caps.iter().next().expect("assertion above").clone();
        assert_eq!(self.crypto, AuthFunctionHMAC256::crypto_capability());
    }
    fn set_olt_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        self.auth.set_olt_challenge(&data);
    }
    fn set_olt_challenge_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }
    fn get_onu_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        let mut onu_challenge = vec![0u8; 16];
        ctx.rng.fill_bytes(&mut onu_challenge);
        self.auth.set_onu_challenge(&onu_challenge);
        return onu_challenge;
    }
    fn get_onu_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        return self.auth.calc_onu_result();
    }
    fn get_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
    ) -> HashSet<CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(self.crypto.clone());
        return ret;
    }
    fn set_olt_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        assert_eq!(self.auth.calc_olt_result(), data, "olt result mismatch"); //FIXME: handle more gracefully
        self.authentication_state = true;
    }
    fn set_olt_result_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }
    fn get_onu_authentication_state(&mut self, ctx: &mut CryptoContext) -> bool {
        return self.authentication_state;
    }
    fn get_master_session_key_name(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        return self.auth.calc_msk_name();
    }
}

#[derive(Default)]
pub struct OLTHMAC {
    auth: AuthFunctionHMAC256,
}

impl OLTHMAC {
    pub fn new(onu_serial: &[u8], psk: &[u8]) -> Self {
        assert_eq!(onu_serial.len(), 8);
        let mut ret = Self::default();
        ret.auth.set_onu_serial(&onu_serial);
        ret.auth.set_psk(&psk);
        return ret;
    }
}

impl OLT for OLTHMAC {
    fn get_olt_crypto_capabilites(&mut self, ctx: &mut CryptoContext) -> HashSet<CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(AuthFunctionHMAC256::crypto_capability());
        return ret;
    }
    fn get_olt_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        let mut olt_challenge = vec![0u8; 16];
        ctx.rng.fill_bytes(&mut olt_challenge);
        self.auth.set_olt_challenge(&olt_challenge);
        return olt_challenge;
    }
    fn get_olt_challenge_status(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }
    fn set_onu_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        self.auth.set_onu_challenge(&data);
    }
    fn set_onu_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        assert_eq!(data, self.auth.calc_onu_result());
    }
    fn set_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps.iter().next().expect("asserted above"),
            &AuthFunctionHMAC256::crypto_capability()
        );
    }
    fn get_olt_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        return self.auth.calc_olt_result();
    }
    fn get_olt_result_status(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }
    fn set_onu_authentication_state(&mut self, ctx: &mut CryptoContext, state: bool) {
        assert!(state);
    }
    fn set_master_session_key_name(&mut self, ctx: &mut CryptoContext, msk_name: Vec<u8>) {
        assert_eq!(self.auth.calc_msk_name(), msk_name);
    }
}
