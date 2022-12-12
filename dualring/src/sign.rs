use elliptic_curve;

#[derive(Clone, Debug)]
pub struct DualRingSignature<C: PrimeCurve + ScalarArithmetic + AffineArithmetic> {
    pub(crate) c_vec: Vec<Scalar<C>>,
    pub(crate) z: Scalar<C>,
}
