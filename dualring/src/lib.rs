#![allow(non_snake_case)]
use elliptic_curve::{Scalar, AffinePoint, PrimeCurve, ScalarArithmetic, AffineArithmetic};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SumArg<C: PrimeCurve + ScalarArithmetic + AffineArithmetic> {
    pub(crate) L_vec: Vec<Scalar<C>>,
    pub(crate) R_vec: Vec<Scalar<C>>,
    pub(crate) a: Scalar<C>,
    pub(crate) b: Scalar<C>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingSignature<C: PrimeCurve + ScalarArithmetic + AffineArithmetic> {
    pub(crate) z: Scalar<C>,
    pub(crate) R: AffinePoint<C>,
    pub(crate) pi: SumArg<C>,
}
