extern crate criterion;
extern crate snow;
extern crate rand_core;
extern crate ninn;
extern crate oqs;

use std::time;

fn main() {
    use oqs::kem::OqsKemAlg as Alg;
    criterion::Criterion::default()
        .with_plots()
        .plotting_backend(criterion::PlottingBackend::Gnuplot)
        .bench_function("gen+decaps kyber-512", |b| b.iter_custom(|n| bench_oqs(n, Alg::Kyber512).0))
        .bench_function("encaps kyber-512",     |b| b.iter_custom(|n| bench_oqs(n, Alg::Kyber512).1))
        .bench_function("gen+decaps sike-P434", |b| b.iter_custom(|n| bench_oqs(n, Alg::SikeP434).0))
        .bench_function("encaps sike-P434",     |b| b.iter_custom(|n| bench_oqs(n, Alg::SikeP434).1));
}

fn bench_oqs(times: u64, alg: oqs::kem::OqsKemAlg) -> (time::Duration, time::Duration) {
    bench_generate_decapsulate(times, || ninn::handshake::Kem::new(alg).unwrap())
}

fn bench_generate_decapsulate<F, K>(times: u64, kem_f: F) -> (time::Duration, time::Duration)
where F: Fn() -> K,
      K: snow::types::Kem
{
    let mut r = rand_core::OsRng;
    let mut total1 = time::Duration::default();
    let mut total2 = time::Duration::default();

    let (mut shared_secret, mut ciphertext);
    {
        let kem = kem_f();
        shared_secret = vec![0u8; kem.shared_secret_len()];
        ciphertext = vec![0u8; kem.ciphertext_len()];
    }

    for _ in 0..times {
        let mut start = time::Instant::now();
        let mut kem = kem_f();
        kem.generate(&mut r);
        total1 += start.elapsed();

        start = time::Instant::now();
        let another_kem = kem_f();
        another_kem.encapsulate(kem.pubkey(), &mut shared_secret, &mut ciphertext).unwrap();
        total2 += start.elapsed();

        start = time::Instant::now();
        kem.decapsulate(&ciphertext, &mut shared_secret).unwrap();
        total1 += start.elapsed();
    }
    (total1, total2)
}
