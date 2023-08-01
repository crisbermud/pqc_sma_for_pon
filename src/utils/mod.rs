use rand::Rng;
use sha2::Digest;
use sha2::Sha256;

pub mod timing;

/// generate a vector of the given length with random bytes
pub fn rand_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    return (0..len).map(move |_| rng.gen()).collect();
}

/// calculate the sha256 hash of the given byte slice as byte vector
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    return hasher.finalize().to_vec();
}
