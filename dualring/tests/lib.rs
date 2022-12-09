#![cfg(feature = "dev")]

use elliptic_curve::dev::MockCurve;

type Signature = dualring::Signature<MockCurve>;
type SignatureBytes = dualring::SignatureBytes<MockCurve>;

#[test]
fn rejects_all_zero_signature() {
    let all_zero_bytes = SignatureBytes::default();
    assert!(Signature::try_from(all_zero_bytes.as_ref()).is_err());
}
