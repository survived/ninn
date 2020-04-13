extern crate env_logger;
extern crate futures;
extern crate ninn;
extern crate tokio;
extern crate webpki;
extern crate enum_iterator;
extern crate criterion;

use futures::future::{ok, loop_fn, Future, Loop};
use enum_iterator::IntoEnumIterator;

use std::env;
use std::thread;

use futures::*;
use std::time::*;

static SERVER_PK: [u8; 32] = [
    0x33, 0x2b, 0x2f, 0x56,
    0xbb, 0x4e, 0x28, 0x4a,
    0x2e, 0x87, 0xe7, 0x69,
    0x0d, 0x51, 0xf1, 0x29,
    0x14, 0xa5, 0x9b, 0x3b,
    0x8e, 0x03, 0x56, 0xd8,
    0x23, 0xe0, 0x32, 0x61,
    0x0a, 0xfd, 0xd6, 0x61
];

fn main() {
    env_logger::init();

    let server = env::args().nth(1).expect("need server name as 1st argument");
    let testsuite_name = env::args().nth(2).expect("need testsuite name as 2nd argument");
    let kem_choice = env::args().nth(3).expect("need kem alg as 3rd argument (or 'none' if kem disabled')");

    let kem_alg = if kem_choice != "none" {
        let (alg, _) = oqs::kem::OqsKemAlg::into_enum_iter()
            .map(|a| (a, a.alg_name()))
            .map(|(a, n)| (a, std::ffi::CStr::from_bytes_with_nul(n).unwrap().to_str().unwrap()))
            .find(|(_, name)| name == &kem_choice)
            .expect("Unknown KEM algorithm");
        Some(alg)
    } else {
        None
    };

    println!("Connect to : {}", server);

    criterion::Criterion::default()
        .with_plots()
        .plotting_backend(criterion::PlottingBackend::Gnuplot)
        .save_baseline(format!("{}_{}", testsuite_name, kem_choice))
        .measurement_time(Duration::from_secs(500))
        .bench_function("handshake_time", |b| b.iter_custom(|n| run_n_times(&server, kem_alg, n)));
}

fn run_n_times(server: &str, kem_alg: Option<oqs::kem::OqsKemAlg>, n: u64) -> std::time::Duration {
    println!("n={}", n);
    let mut runtime = tokio::runtime::Builder::new()
        .core_threads(2)
        .build()
        .unwrap();
    let mut total = Duration::default();
    for _ in 0..n {
        let future = ninn::Client::connect(server, 8888, SERVER_PK, None, kem_alg)
            .expect("cannot connect to server");
        let (client, _) = runtime.block_on(future)
            .expect("connection failed");
        total += client.handshake_duration().expect("handshake is not finished");
    }
    runtime.shutdown_now()
        .wait().unwrap();
    total
}
