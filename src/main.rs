mod omci;
mod utils;

use utils::timing::{Metric, MetricAccumulation};

use crate::omci::{OLT, ONU};
use crate::utils::rand_bytes;
use crate::utils::timing::CountingRng;
use crate::utils::timing::{time_get_set, CryptoContext};

#[derive(Default, Debug)]
pub struct Times {
    olt: Metric,
    onu: Metric,
}

#[derive(Default, Debug)]
pub struct TimesAccumulation {
    olt: MetricAccumulation,
    onu: MetricAccumulation,
}

impl std::ops::AddAssign<Times> for TimesAccumulation {
    fn add_assign(&mut self, rhs: Times) {
        self.olt += rhs.olt;
        self.onu += rhs.onu;
    }
}

impl TimesAccumulation {
    fn stats(&self, prefix: &str) -> Vec<String> {
        let mut ret = self.olt.stats(&format!("{}\t{}", prefix, "olt"));
        ret.append(&mut self.onu.stats(&format!("{}\t{}", prefix, "onu")));
        return ret;
    }
}

/// run an OMCI-based SMA handshake between the given OLT and ONU and track metrics
fn negotiate<OT, OU>(olt: &mut OT, onu: &mut OU, times: &mut Times)
where
    OT: OLT,
    OU: ONU,
{
    let mut olt_with_time = (olt, &mut times.olt);
    let mut onu_with_time = (onu, &mut times.onu);
    let mut rng = CountingRng::from(rand::thread_rng());

    macro_rules! up {
        ($get:expr, $set:expr) => {
            time_get_set(
                &mut onu_with_time,
                &mut $get,
                &mut olt_with_time,
                &mut $set,
                &mut CryptoContext { rng: &mut rng },
            );
        };
    }
    macro_rules! down {
        ($get:expr, $set:expr) => {
            time_get_set(
                &mut olt_with_time,
                &mut $get,
                &mut onu_with_time,
                &mut $set,
                &mut CryptoContext { rng: &mut rng },
            );
        };
    }

    down!(
        OT::get_olt_crypto_capabilites,
        OU::set_olt_crypto_capabilites
    );
    down!(OT::get_olt_random_challenge, OU::set_olt_random_challenge);
    down!(OT::get_olt_challenge_status, OU::set_olt_challenge_status);
    up!(OU::get_onu_random_challenge, OT::set_onu_random_challenge);
    up!(
        OU::get_onu_authentication_result,
        OT::set_onu_authentication_result
    );
    up!(
        OU::get_onu_selected_crypto_capabilites,
        OT::set_onu_selected_crypto_capabilites
    );
    down!(
        OT::get_olt_authentication_result,
        OU::set_olt_authentication_result
    );
    down!(OT::get_olt_result_status, OU::set_olt_result_status);
    up!(
        OU::get_onu_authentication_state,
        OT::set_onu_authentication_state
    );
    up!(
        OU::get_master_session_key_name,
        OT::set_master_session_key_name
    );
}

/// generate new OLT and ONU using the kyber algorithm, perform a handshake and track the metrics
fn run_kyber(times: &mut Times) {
    let mut olt = omci::OLTKyber::default();
    let mut onu = omci::ONUKyber::default();
    olt.gen_keypair();
    onu.gen_keypair();
    olt.set_other_pubkey(onu.get_pubkey());
    onu.set_other_pubkey(olt.get_pubkey());

    negotiate(&mut olt, &mut onu, times);
}

/// generate new OLT and ONU using the HMAC algorithm, perform a handshake and track the metrics
fn run_hmac(times: &mut Times) {
    let onu_serial: Vec<u8> = vec![1, 1, 3, 4, 5, 6, 7, 8];
    let psk = rand_bytes(16);

    let mut olt = omci::OLTHMAC::new(&onu_serial, &psk);
    let mut onu = omci::ONUHMAC::new(&onu_serial, &psk);

    negotiate(&mut olt, &mut onu, times);
}

/// generate new OLT and ONU using the 25519 algorithm, perform a handshake and track the metrics
fn run_25519(times: &mut Times) {
    let mut olt = omci::OLT25519::default();
    let mut onu = omci::ONU25519::default();
    olt.gen_keypair();
    onu.gen_keypair();
    olt.set_other_pubkey(onu.get_pubkey());
    onu.set_other_pubkey(olt.get_pubkey());

    negotiate(&mut olt, &mut onu, times);
}

fn print_lines(lines: &[String]) {
    for line in lines {
        println!("{}", line);
    }
}

fn main() {
    const RUNS: u32 = 10000;
    let mut times_hmac = TimesAccumulation::default();
    let mut times_kyber = TimesAccumulation::default();
    let mut times_25519 = TimesAccumulation::default();
    for _ in 0..RUNS {
        let mut t = Times::default();
        run_hmac(&mut t);
        times_hmac += t;
        t = Times::default();
        run_kyber(&mut t);
        times_kyber += t;
        t = Times::default();
        run_25519(&mut t);
        times_25519 += t;
    }
    println!("algo\tdev\tmetric\tmin\tq1\tmedian\tq3\tmax");
    print_lines(&times_hmac.stats("hmac"));
    print_lines(&times_kyber.stats("kyber"));
    print_lines(&times_25519.stats("25519"));
}
