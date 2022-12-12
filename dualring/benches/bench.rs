#[macro_use]
extern crate criterion;

use ark_bls12_381::g1::Parameters as Param381;
use ark_ff::fields::Field;
use ark_ff::fields::PrimeField;
use ark_std::rand::RngCore;
use ark_std::test_rng;
use ark_std::UniformRand;
use ark_test_curves::bls12_381::Fq;
use criterion::Criterion;

criterion_main!(bench);
fn bench_prove(c: &mut Criterion) {
}
