use crypto_bigint::{Encoding, U256};

#[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
use crypto_bigint::risc0::modmul_u256;

// Used for testing
#[cfg(not(all(target_os = "zkvm", target_arch = "riscv32")))]
fn modmul_u256(lhs: &U256, rhs: &U256, modulus: &U256) -> U256 {
    use crypto_bigint::{NonZero, U512};

    let modulus_wide = NonZero::from_uint(U256::ZERO.concat(modulus));
    let product_wide: U512 = (lhs * rhs).rem(&modulus_wide);
    let (_, lo) = product_wide.split();
    lo
}

pub const SECP256K1_CURVE_ORDER: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

pub fn schnorr_signature(
    secret_key: [u8; 32],
    secret_nonce: [u8; 32],
    challenge: [u8; 32],
) -> [u8; 32] {
    let d = U256::from_be_bytes(secret_key);
    let r = U256::from_be_bytes(secret_nonce);
    let e = U256::from_be_bytes(challenge);

    let s = r.add_mod(
        &modmul_u256(&e, &d, &SECP256K1_CURVE_ORDER),
        &SECP256K1_CURVE_ORDER,
    );
    s.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modmul_u256() {
        let a =
            U256::from_be_hex("1986eb08577d1e4543b7ce1c5bd73ed77b608508dcc1810560b7eba5ae3c6779");
        let b =
            U256::from_be_hex("1512250aa7c1eb284a5b8829f5aee3f8c14414bdac7736513860881aab0b58ce");
        let c =
            U256::from_be_hex("3f221863017d87ecdea67c04cb68c58c105be050c8ec43e3b69e1bf2e0b96f5b");
        assert_eq!(modmul_u256(&a, &b, &SECP256K1_CURVE_ORDER), c);
    }
}

// TODO
// pub const ED25519_CURVE_ORDER: U256 =
//     U256::from_be_hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
