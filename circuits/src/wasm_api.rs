use ff::PrimeField;
use halo2_proofs::circuit::Value;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use wasm_bindgen::prelude::*;

use crate::badge::{identity, leaf_of, nullifier_of, root_and_path, BadgeCircuit, DEPTH, K};

// ---------- small helpers ----------

fn err<E: std::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{e:?}"))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex digit".to_string()))
        .collect()
}

fn fp_to_hex(x: Fp) -> String {
    bytes_to_hex(&x.to_repr())
}

fn fp_from_hex(s: &str) -> Result<Fp, String> {
    let bytes = hex_to_bytes(s)?;
    if bytes.len() != 32 {
        return Err("a field element must be exactly 64 hex characters".to_string());
    }
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    let parsed: Option<Fp> = Fp::from_repr(repr).into();
    parsed.ok_or_else(|| "value is not a valid field element".to_string())
}

fn parse_u64(s: &str) -> Result<u64, String> {
    s.trim().parse::<u64>().map_err(|_| format!("not a valid u64: {s}"))
}

fn parse_fp_list(csv: &str) -> Result<[Fp; DEPTH], String> {
    let items: Result<Vec<Fp>, String> = csv.split(',').map(fp_from_hex).collect();
    items?
        .try_into()
        .map_err(|_| format!("expected exactly {DEPTH} values"))
}

fn parse_bits(csv: &str) -> Result<[Fp; DEPTH], String> {
    let items: Result<Vec<Fp>, String> = csv
        .split(',')
        .map(|b| match b.trim() {
            "0" => Ok(Fp::from(0u64)),
            "1" => Ok(Fp::from(1u64)),
            _ => Err("each index bit must be 0 or 1".to_string()),
        })
        .collect();
    items?
        .try_into()
        .map_err(|_| format!("expected exactly {DEPTH} bits"))
}

fn public_inputs(
    root: Fp,
    badge_type: u64,
    threshold: u64,
    scope: u64,
    nullifier: Fp,
) -> Vec<Fp> {
    vec![
        root,
        Fp::from(badge_type),
        Fp::from(threshold),
        Fp::from(scope),
        nullifier,
    ]
}

// ---------- functions JavaScript can call ----------

/// Builds the demo issuer tree: 16 credentials, slot `index` belongs to the holder.
/// Returns "root_hex;sibling0,sibling1,sibling2,sibling3;bit0,bit1,bit2,bit3".
#[wasm_bindgen]
pub fn demo_tree(
    secret_hex: &str,
    badge_type: &str,
    value: &str,
    index: u32,
) -> Result<String, JsValue> {
    let secret = fp_from_hex(secret_hex).map_err(err)?;
    let badge = parse_u64(badge_type).map_err(err)?;
    let value = parse_u64(value).map_err(err)?;
    let index = index as usize;
    if index >= (1usize << DEPTH) {
        return Err(err("index must be between 0 and 15"));
    }

    let badge_f = Fp::from(badge);
    let leaves: Vec<Fp> = (0..(1usize << DEPTH))
        .map(|i| {
            if i == index {
                leaf_of(identity(secret), badge_f, value)
            } else {
                leaf_of(identity(Fp::from(7000 + i as u64)), badge_f, 100 + i as u64)
            }
        })
        .collect();

    let (root, siblings, bits) = root_and_path(&leaves, index);
    let sibs: Vec<String> = siblings.iter().map(|s| fp_to_hex(*s)).collect();
    let bits: Vec<String> = bits
        .iter()
        .map(|b| if *b == Fp::from(0u64) { "0" } else { "1" }.to_string())
        .collect();
    Ok(format!("{};{};{}", fp_to_hex(root), sibs.join(","), bits.join(",")))
}

/// nullifier = Poseidon(secret, badge_type, scope), as hex.
#[wasm_bindgen]
pub fn nullifier_hex(secret_hex: &str, badge_type: &str, scope: &str) -> Result<String, JsValue> {
    let secret = fp_from_hex(secret_hex).map_err(err)?;
    let badge = parse_u64(badge_type).map_err(err)?;
    let scope = parse_u64(scope).map_err(err)?;
    Ok(fp_to_hex(nullifier_of(secret, Fp::from(badge), Fp::from(scope))))
}

/// Holds the proving parameters and keys, so the slow setup only runs once per page.
#[wasm_bindgen]
pub struct BadgeProver {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

#[wasm_bindgen]
impl BadgeProver {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BadgeProver, JsValue> {
        let params: Params<EqAffine> = Params::new(K);
        let empty = BadgeCircuit::default();
        let vk = keygen_vk(&params, &empty).map_err(err)?;
        let pk = keygen_pk(&params, vk, &empty).map_err(err)?;
        Ok(BadgeProver { params, pk })
    }

    /// Creates a proof. Returns it as a hex string.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        secret_hex: &str,
        badge_type: &str,
        value: &str,
        threshold: &str,
        scope: &str,
        root_hex: &str,
        siblings_csv: &str,
        bits_csv: &str,
    ) -> Result<String, JsValue> {
        let secret = fp_from_hex(secret_hex).map_err(err)?;
        let badge = parse_u64(badge_type).map_err(err)?;
        let value = parse_u64(value).map_err(err)?;
        let threshold = parse_u64(threshold).map_err(err)?;
        let scope = parse_u64(scope).map_err(err)?;
        let root = fp_from_hex(root_hex).map_err(err)?;
        let siblings = parse_fp_list(siblings_csv).map_err(err)?;
        let bits = parse_bits(bits_csv).map_err(err)?;

        let nullifier = nullifier_of(secret, Fp::from(badge), Fp::from(scope));
        let inst = public_inputs(root, badge, threshold, scope, nullifier);

        let circuit = BadgeCircuit {
            secret: Value::known(secret),
            badge_type: Value::known(Fp::from(badge)),
            scope: Value::known(Fp::from(scope)),
            value: Value::known(value),
            threshold: Value::known(threshold),
            siblings: siblings.map(Value::known),
            bits: bits.map(Value::known),
        };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &[&[&inst[..]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .map_err(err)?;
        Ok(bytes_to_hex(&transcript.finalize()))
    }

    /// Checks a proof against the public inputs. Returns true or false.
    pub fn verify(
        &self,
        proof_hex: &str,
        root_hex: &str,
        badge_type: &str,
        threshold: &str,
        scope: &str,
        nullifier_hex: &str,
    ) -> Result<bool, JsValue> {
        let proof = hex_to_bytes(proof_hex).map_err(err)?;
        let root = fp_from_hex(root_hex).map_err(err)?;
        let badge = parse_u64(badge_type).map_err(err)?;
        let threshold = parse_u64(threshold).map_err(err)?;
        let scope = parse_u64(scope).map_err(err)?;
        let nullifier = fp_from_hex(nullifier_hex).map_err(err)?;
        let inst = public_inputs(root, badge, threshold, scope, nullifier);

        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        Ok(verify_proof(
            &self.params,
            self.pk.get_vk(),
            strategy,
            &[&[&inst[..]]],
            &mut transcript,
        )
        .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "3930000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn api_roundtrip() {
        let prover = BadgeProver::new().ok().expect("setup");

        let tree = demo_tree(SECRET, "1", "750", 5).ok().expect("tree");
        let parts: Vec<&str> = tree.split(';').collect();
        assert_eq!(parts.len(), 3);
        let (root, sibs, bits) = (parts[0], parts[1], parts[2]);

        let nf = nullifier_hex(SECRET, "1", "99").ok().expect("nullifier");

        let proof = prover
            .prove(SECRET, "1", "750", "500", "99", root, sibs, bits)
            .ok()
            .expect("prove");

        // Right public inputs: accepted.
        let ok = prover.verify(&proof, root, "1", "500", "99", &nf).ok().unwrap();
        assert!(ok);

        // Same proof claimed for a different scope: rejected.
        let nf_other = nullifier_hex(SECRET, "1", "100").ok().unwrap();
        let bad_scope = prover.verify(&proof, root, "1", "500", "100", &nf_other).ok().unwrap();
        assert!(!bad_scope);

        // Same proof claimed for a higher threshold: rejected.
        let bad_thr = prover.verify(&proof, root, "1", "600", "99", &nf).ok().unwrap();
        assert!(!bad_thr);
    }

    #[test]
    fn hex_roundtrip() {
        let x = Fp::from(123456789u64);
        assert_eq!(fp_from_hex(&fp_to_hex(x)).unwrap(), x);
    }
}
