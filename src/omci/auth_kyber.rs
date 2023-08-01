use std::collections::HashSet;

use pqc_kyber::Ake;
use pqc_kyber::Keypair;
use pqc_kyber::PublicKey;

use super::CryptoCapability;
use super::CryptoContext;
use super::OLT;
use super::ONU;
use crate::utils::sha256;

#[derive(Default)]
struct CyberCommon {
    ake: Ake,
    my_keypair: Option<Keypair>,
    their_pubkey: Option<PublicKey>,
}

#[derive(Default)]
pub struct ONUKyber {
    common: CyberCommon,
    challenge: Option<Vec<u8>>,
}

impl ONUKyber {
    pub fn gen_keypair(&mut self) {
        self.common.my_keypair = Some(pqc_kyber::keypair(&mut rand::thread_rng()));
    }

    pub fn get_pubkey(&self) -> PublicKey {
        return self.common.my_keypair.unwrap().public.clone();
    }

    pub fn set_other_pubkey(&mut self, pubkey: PublicKey) {
        self.common.their_pubkey = Some(pubkey);
    }
}

impl ONU for ONUKyber {
    fn set_olt_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<super::CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        assert_eq!(
            caps.iter().next().expect("assertion above"),
            &CryptoCapability::KYBER
        );
    }

    fn set_olt_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        self.challenge = Some(data);
    }

    fn set_olt_challenge_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }

    fn get_onu_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        // Part 2 of two-way auth
        self.common
            .ake
            .server_receive(
                std::mem::replace(&mut self.challenge, None)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                &self.common.their_pubkey.unwrap(),
                &self.common.my_keypair.unwrap().secret,
                &mut ctx.rng,
            )
            .unwrap()
            .into()
    }

    fn get_onu_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        // Ignore this as we only need 2-way (already verified in set_onu_random_challenge)
        vec![]
    }

    fn get_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
    ) -> HashSet<super::CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(CryptoCapability::KYBER);
        return ret;
    }

    fn set_olt_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        // Ignore this as we only need 2-way (already verified in set_onu_random_challenge)
    }

    fn set_olt_result_status(&mut self, ctx: &mut CryptoContext, status: bool) {
        assert!(status);
    }

    fn get_onu_authentication_state(&mut self, ctx: &mut CryptoContext) -> bool {
        return true; //FIXME: actually check this and don't use assertions
    }

    fn get_master_session_key_name(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        sha256(&self.common.ake.shared_secret)
    }
}

#[derive(Default)]
pub struct OLTKyber {
    common: CyberCommon,
}

impl OLTKyber {
    pub fn gen_keypair(&mut self) {
        self.common.my_keypair = Some(pqc_kyber::keypair(&mut rand::thread_rng()));
    }

    pub fn get_pubkey(&self) -> PublicKey {
        return self.common.my_keypair.unwrap().public.clone();
    }

    pub fn set_other_pubkey(&mut self, pubkey: PublicKey) {
        self.common.their_pubkey = Some(pubkey);
    }
}

impl OLT for OLTKyber {
    fn get_olt_crypto_capabilites(&mut self, ctx: &mut CryptoContext) -> HashSet<CryptoCapability> {
        let mut ret = HashSet::new();
        ret.insert(CryptoCapability::KYBER);
        return ret;
    }

    fn get_olt_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        // Part 1 of two-way auth
        self.common
            .ake
            .client_init(&self.common.their_pubkey.unwrap(), &mut ctx.rng)
            .into()
    }

    fn get_olt_challenge_status(&mut self, ctx: &mut CryptoContext) -> bool {
        return true;
    }

    fn set_onu_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>) {
        // Part 3 of two-way auth
        self.common
            .ake
            .client_confirm(
                data.try_into().unwrap(),
                &self.common.my_keypair.unwrap().secret,
            )
            .unwrap();
    }

    fn set_onu_authentication_result(&mut self, ctx: &mut CryptoContext, _: Vec<u8>) {
        // Ignore this as we only need 2-way (already verified in set_onu_random_challenge)
    }

    fn set_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<super::CryptoCapability>,
    ) {
        assert_eq!(caps.len(), 1);
        assert_eq!(caps.iter().next().unwrap(), &CryptoCapability::KYBER);
    }

    fn get_olt_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8> {
        // Ignore this as we only need 2-way (already verified in set_onu_random_challenge)
        vec![]
    }

    fn get_olt_result_status(&mut self, ctx: &mut CryptoContext) -> bool {
        // FIXME actually check this instead of asserting
        return true;
    }

    fn set_onu_authentication_state(&mut self, ctx: &mut CryptoContext, state: bool) {
        assert!(state);
    }

    fn set_master_session_key_name(&mut self, ctx: &mut CryptoContext, msk_name: Vec<u8>) {
        let ours = sha256(&self.common.ake.shared_secret);
        assert_eq!(ours, msk_name);
    }
}
