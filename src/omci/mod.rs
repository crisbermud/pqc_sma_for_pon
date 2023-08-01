use std::collections::HashSet;

mod auth_hmac;
pub use auth_hmac::OLTHMAC;
pub use auth_hmac::ONUHMAC;

mod auth_kyber;
pub use auth_kyber::OLTKyber;
pub use auth_kyber::ONUKyber;

mod auth_25519;
pub use auth_25519::OLT25519;
pub use auth_25519::ONU25519;

use crate::utils::timing::CryptoContext;

// Value is bit position
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum CryptoCapability {
    AES_CMAC_128 = 1,
    HMAC_SHA_256 = 2,
    HMAC_SHA_512 = 3,
    // rest reserved
    // our suggestion:
    DHE_ED25519 = 4,
    KYBER = 5,
}

impl Default for CryptoCapability {
    fn default() -> Self {
        return Self::HMAC_SHA_256;
    }
}

/// trait representing the relevant parts of an ONU to perform OMCI-based shared mutual authentication
pub trait ONU {
    fn set_olt_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    );
    fn set_olt_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>);
    fn set_olt_challenge_status(&mut self, ctx: &mut CryptoContext, status: bool);
    fn get_onu_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8>;
    fn get_onu_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8>;
    fn get_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
    ) -> HashSet<CryptoCapability>;
    fn set_olt_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>);
    fn set_olt_result_status(&mut self, ctx: &mut CryptoContext, status: bool);
    fn get_onu_authentication_state(&mut self, ctx: &mut CryptoContext) -> bool;
    fn get_master_session_key_name(&mut self, ctx: &mut CryptoContext) -> Vec<u8>;
}

/// trait representing the relevant parts of an OLT to perform OMCI-based shared mutual authentication
pub trait OLT {
    fn get_olt_crypto_capabilites(&mut self, ctx: &mut CryptoContext) -> HashSet<CryptoCapability>;
    fn get_olt_random_challenge(&mut self, ctx: &mut CryptoContext) -> Vec<u8>;
    fn get_olt_challenge_status(&mut self, ctx: &mut CryptoContext) -> bool;
    fn set_onu_random_challenge(&mut self, ctx: &mut CryptoContext, data: Vec<u8>);
    fn set_onu_authentication_result(&mut self, ctx: &mut CryptoContext, data: Vec<u8>);
    fn set_onu_selected_crypto_capabilites(
        &mut self,
        ctx: &mut CryptoContext,
        caps: HashSet<CryptoCapability>,
    );
    fn get_olt_authentication_result(&mut self, ctx: &mut CryptoContext) -> Vec<u8>;
    fn get_olt_result_status(&mut self, ctx: &mut CryptoContext) -> bool;
    fn set_onu_authentication_state(&mut self, ctx: &mut CryptoContext, state: bool);
    fn set_master_session_key_name(&mut self, ctx: &mut CryptoContext, msk_name: Vec<u8>);
}
