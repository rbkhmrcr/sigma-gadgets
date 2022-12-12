// This is heavily based off https://github.com/dalek-cryptography/bulletproofs,
// but adapting the logarithmic size inner product argument to the logarithmic 
// sized sum argument.

use elliptic_curve;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SumArgument<C: PrimeCurve + ScalarArithmetic + AffineArithmetic> {
    pub(crate) L_vec: Vec<Scalar<C>>,
    pub(crate) R_vec: Vec<Scalar<C>>,
    pub(crate) a: Scalar<C>,,
}

impl SumArgument {
    /// The sum argument is almost equivalent to the inner product argument 
    /// of Bulletproofs, but rather than proving c = <a, b>, it works to 
    /// prove that c = <a, 1^n>, eliminating about half of the computation.
    ///
    /// The length of a must be a power of two.
    pub fn create(
        mut G_vec: Vec<AffinePoint>,
        mut u: AffinePoint,
        mut a_vec: Vec<Scalar>,
    ) -> SumArgument {
        // Create slices G, a backed by their respective vectors.  This lets us 
        // reslice as we compress the lengths of the vectors in the main loop below.
        let mut G = &mut G_vec[..];
        let mut a = &mut a_vec[..];
        let mut n = G.len();
        
        let mut b = [Scalar::ONE, n];

        // All of the input vectors must have the same length.
        assert_eq!(G.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);

        // All of the input vectors must have a length that is a power of two.
        assert!(n.is_power_of_two());
        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        while n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let L = Point::vartime_multiscalar_mul(
                a_L.iter().chain(iter::once(&c_L)),
                G_R.iter().chain(iter::once(u)),
            )
            .compress();

            let R = Point::vartime_multiscalar_mul(
                a_R.iter().chain(iter::once(&c_R)),
                G_L.iter().chain(iter::once(u)),
            )
            .compress();

            L_vec.push(L);
            R_vec.push(R);
            
            let x_inv = x.invert();

            for i in 0..n {
                a_L[i] = a_L[i] * x + x_inv * a_R[i];
                b_L[i] = b_L[i] * x_inv + x * b_R[i];
                G_L[i] = Point::vartime_multiscalar_mul(&[u_inv, u], &[G_L[i], G_R[i]]);
            }

            a = a_L;
            b = b_L;
            G = G_L;
        }

        SumArgument {
            L_vec: L_vec,
            R_vec: R_vec,
            a: a[0],
            b: b[0],
        }
    }
}
    
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    let mut out = Scalar::ZERO;
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}
