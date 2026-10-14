use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

/// Tree depth: 4 levels, so 16 credentials.
pub const DEPTH: usize = 4;

/// Rows in the circuit: 2^K. Four Poseidon hashes need more than K = 8 to be safe.
pub const K: u32 = 9;

/// Poseidon hash of two values, computed outside the circuit.
pub fn hash2(a: Fp, b: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

/// Builds the full tree natively. Returns (root, siblings, index bits) for one leaf.
/// bits[d] = 1 means the node at level d is the RIGHT child of its parent.
pub fn root_and_path(leaves: &[Fp], index: usize) -> (Fp, [Fp; DEPTH], [Fp; DEPTH]) {
    assert_eq!(leaves.len(), 1 << DEPTH);
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut idx = index;
    let mut siblings = [Fp::from(0u64); DEPTH];
    let mut bits = [Fp::from(0u64); DEPTH];
    for d in 0..DEPTH {
        siblings[d] = level[idx ^ 1];
        bits[d] = Fp::from((idx & 1) as u64);
        level = level.chunks(2).map(|p| hash2(p[0], p[1])).collect();
        idx >>= 1;
    }
    (level[0], siblings, bits)
}

/// Private inputs: leaf, siblings, bits. Public input (instance row 0): root.
#[derive(Clone, Default)]
pub struct MerkleCircuit {
    pub leaf: Value<Fp>,
    pub siblings: [Value<Fp>; DEPTH],
    pub bits: [Value<Fp>; DEPTH],
}

#[derive(Clone)]
pub struct MerkleConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    cur: Column<Advice>,
    sib: Column<Advice>,
    bit: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    s_swap: Selector,
    instance: Column<Instance>,
}

impl Circuit<Fp> for MerkleCircuit {
    type Config = MerkleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Poseidon chip columns.
        let state: [Column<Advice>; 3] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let rc_a: Vec<_> = (0..3).map(|_| meta.fixed_column()).collect();
        let rc_b: Vec<_> = (0..3).map(|_| meta.fixed_column()).collect();
        meta.enable_constant(rc_b[0]);

        let poseidon: Pow5Config<Fp, 3, 2> = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        // Our own columns for the swap step.
        let cur = meta.advice_column();
        let sib = meta.advice_column();
        let bit = meta.advice_column();
        let left = meta.advice_column();
        let right = meta.advice_column();
        let s_swap = meta.selector();

        let instance = meta.instance_column();

        meta.enable_equality(cur);
        meta.enable_equality(left);
        meta.enable_equality(right);
        meta.enable_equality(instance);

        meta.create_gate("merkle swap", |meta| {
            let s = meta.query_selector(s_swap);
            let q_cur = meta.query_advice(cur, Rotation::cur());
            let q_sib = meta.query_advice(sib, Rotation::cur());
            let q_bit = meta.query_advice(bit, Rotation::cur());
            let q_left = meta.query_advice(left, Rotation::cur());
            let q_right = meta.query_advice(right, Rotation::cur());
            let one = Expression::Constant(Fp::from(1u64));

            vec![
                // the bit is 0 or 1
                s.clone() * (q_bit.clone() * (q_bit.clone() - one)),
                // left = cur + bit * (sib - cur)
                s.clone()
                    * (q_left
                        - (q_cur.clone() + q_bit.clone() * (q_sib.clone() - q_cur.clone()))),
                // right = sib + bit * (cur - sib)
                s * (q_right - (q_sib.clone() + q_bit * (q_cur - q_sib))),
            ]
        });

        MerkleConfig {
            poseidon,
            cur,
            sib,
            bit,
            left,
            right,
            s_swap,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Start from the leaf.
        let mut current: AssignedCell<Fp, Fp> = layouter.assign_region(
            || "load leaf",
            |mut region| region.assign_advice(|| "leaf", config.cur, 0, || self.leaf),
        )?;

        for level in 0..DEPTH {
            // Order the pair: put the current node and its sibling on the left or right.
            let (left, right) = layouter.assign_region(
                || format!("swap_{level}"),
                |mut region| {
                    config.s_swap.enable(&mut region, 0)?;

                    let cur_v: Value<Fp> = current.value().copied();
                    let sib_v = self.siblings[level];
                    let bit_v = self.bits[level];

                    // Tie this row's `cur` to the previous hash output.
                    let cur_cell = region.assign_advice(|| "cur", config.cur, 0, || cur_v)?;
                    region.constrain_equal(cur_cell.cell(), current.cell())?;

                    region.assign_advice(|| "sibling", config.sib, 0, || sib_v)?;
                    region.assign_advice(|| "bit", config.bit, 0, || bit_v)?;

                    let left_v = cur_v + bit_v * (sib_v - cur_v);
                    let right_v = sib_v + bit_v * (cur_v - sib_v);
                    let left = region.assign_advice(|| "left", config.left, 0, || left_v)?;
                    let right = region.assign_advice(|| "right", config.right, 0, || right_v)?;
                    Ok((left, right))
                },
            )?;

            // parent = Poseidon(left, right)
            let chip = Pow5Chip::construct(config.poseidon.clone());
            let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                chip,
                layouter.namespace(|| format!("init_{level}")),
            )?;
            current = hasher.hash(
                layouter.namespace(|| format!("hash_{level}")),
                [left, right],
            )?;
        }

        // The final hash must equal the public root.
        layouter.constrain_instance(current.cell(), config.instance, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::EqAffine;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::rngs::SysRng;
    use rand_core::UnwrapErr;
    use std::time::Instant;

    fn leaves() -> Vec<Fp> {
        (0..(1u64 << DEPTH)).map(|i| Fp::from(1000 + i)).collect()
    }

    fn circuit(leaf: Fp, siblings: [Fp; DEPTH], bits: [Fp; DEPTH]) -> MerkleCircuit {
        MerkleCircuit {
            leaf: Value::known(leaf),
            siblings: siblings.map(Value::known),
            bits: bits.map(Value::known),
        }
    }

    #[test]
    fn merkle_accepts_valid_paths() {
        let leaves = leaves();
        for index in [0usize, 5, 15] {
            let (root, siblings, bits) = root_and_path(&leaves, index);
            let c = circuit(leaves[index], siblings, bits);
            let prover = MockProver::run(K, &c, vec![vec![root]]).unwrap();
            assert_eq!(prover.verify(), Ok(()), "leaf index {index}");
        }
    }

    #[test]
    fn merkle_rejects_wrong_leaf() {
        let leaves = leaves();
        let (root, siblings, bits) = root_and_path(&leaves, 5);
        let c = circuit(leaves[5] + Fp::from(1u64), siblings, bits);
        let prover = MockProver::run(K, &c, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_rejects_wrong_sibling() {
        let leaves = leaves();
        let (root, mut siblings, bits) = root_and_path(&leaves, 5);
        siblings[2] += Fp::from(1u64);
        let c = circuit(leaves[5], siblings, bits);
        let prover = MockProver::run(K, &c, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_rejects_flipped_index_bit() {
        let leaves = leaves();
        let (root, siblings, mut bits) = root_and_path(&leaves, 5);
        bits[0] = Fp::from(1u64) - bits[0];
        let c = circuit(leaves[5], siblings, bits);
        let prover = MockProver::run(K, &c, vec![vec![root]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_rejects_wrong_root() {
        let leaves = leaves();
        let (root, siblings, bits) = root_and_path(&leaves, 5);
        let c = circuit(leaves[5], siblings, bits);
        let prover = MockProver::run(K, &c, vec![vec![root + Fp::from(1u64)]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn merkle_real_proof_roundtrip() {
        let leaves = leaves();
        let (root, siblings, bits) = root_and_path(&leaves, 5);
        let inst = [root];
        let c = circuit(leaves[5], siblings, bits);

        let t = Instant::now();
        let params: Params<EqAffine> = Params::new(K);
        let empty = MerkleCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("keygen_pk");
        println!("merkle setup + keygen: {:?}", t.elapsed());

        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[c],
            &[&[&inst[..]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .expect("proof generation");
        let proof: Vec<u8> = transcript.finalize();
        println!(
            "merkle prove: {:?}, proof size: {} bytes",
            t.elapsed(),
            proof.len()
        );

        let t = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&inst[..]]], &mut transcript).is_ok()
        );
        println!("merkle verify: {:?}", t.elapsed());

        // The same proof claimed for a different root: rejected.
        let wrong = [root + Fp::from(1u64)];
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&wrong[..]]], &mut transcript)
                .is_err()
        );
    }
}
