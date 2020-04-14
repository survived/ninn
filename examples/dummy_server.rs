
// Server that just accepts connections.
// Useful for handshake measurement.

extern crate env_logger;
extern crate ninn;
extern crate tokio;
extern crate futures;
extern crate hex;
extern crate enum_iterator;

use enum_iterator::IntoEnumIterator;

use std::time::*;
use futures::prelude::*;
use std::thread;

#[derive(Clone)]
struct Authenticator {}

impl ninn::ClientAuthenticator for Authenticator {
    fn auth(&self, pk : Option<&[u8; 32]>) -> bool {
        println!("auth : {:?}", pk);
        true
    }
}

fn main() {
    let server_sk = [
        0x08, 0x65, 0x45, 0xae,
        0xc9, 0xe6, 0x92, 0x73,
        0x84, 0x69, 0xce, 0xa3,
        0x91, 0x77, 0x45, 0x8d,
        0xbe, 0xaa, 0xde, 0x23,
        0xad, 0x42, 0x55, 0xbc,
        0xf2, 0x28, 0xa9, 0x49,
        0xc7, 0x0f, 0x3c, 0x74
    ];

    env_logger::init();

    let kem_choice = std::env::args().nth(1);
    let kem_alg = if let Some(kem_choice) = kem_choice  {
        let (alg, _) = oqs::kem::OqsKemAlg::into_enum_iter()
            .map(|a| (a, a.alg_name()))
            .map(|(a, n)| (a, std::ffi::CStr::from_bytes_with_nul(n).unwrap().to_str().unwrap()))
            .find(|(_, name)| name == &kem_choice)
            .expect("Unknown KEM algorithm");
        Some(alg)
    } else {
        None
    };

    let auth = Authenticator{};

    let server = ninn::Server::new("127.0.0.1", 8888, server_sk, auth, kem_alg)
        .unwrap().for_each(|_| Ok(()));
    tokio::run(server);
}
