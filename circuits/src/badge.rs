use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

pub use crate::merkle::{hash2, root_and_path, DEPTH};

/// diff = value - threshold must fit in this many bits.
pub const RANGE_BITS: usize = 64;

/// Rows in the circuit: 2^K. Nine Poseidon permutations need more than 512 rows.
pub const K: u32 = 10;

// ---------- native helpers (computed outside the circuit) ----------

pub fn hash1(a: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<1>, 3, 2>::init().hash([a])
}

pub fn hash3(a: Fp, b: Fp, c: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([a, b, c])
}

/// id = Poseidon(secret). The holder gives this to the issuer, never the secret.
pub fn identity(secret: Fp) -> Fp {
    hash1(secret)
}

/// leaf = Poseidon(id, badge_type, value). This is what the issuer puts in the tree.
pub fn leaf_of(id: Fp, badge_type: Fp, value: u64) -> Fp {
    hash3(id, badge_type, Fp::from(value))
}

/// nullifier = Poseidon(secret, badge_type, scope).
pub fn nullifier_of(secret: Fp, badge_type: Fp, scope: Fp) -> Fp {
    hash3(secret, badge_type, scope)
}

// ---------- in-circuit hash helpers ----------

fn hash1c(
    cfg: &Pow5Config<Fp, 3, 2>,
    mut layouter: impl Layouter<Fp>,
    message: [AssignedCell<Fp, Fp>; 1],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let chip = Pow5Chip::construct(cfg.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<1>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init"),
    )?;
    hasher.hash(layouter.namespace(|| "hash"), message)
}

fn hash2c(
    cfg: &Pow5Config<Fp, 3, 2>,
    mut layouter: impl Layouter<Fp>,
    message: [AssignedCell<Fp, Fp>; 2],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let chip = Pow5Chip::construct(cfg.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init"),
    )?;
    hasher.hash(layouter.namespace(|| "hash"), message)
}

fn hash3c(
    cfg: &Pow5Config<Fp, 3, 2>,
    mut layouter: impl Layouter<Fp>,
    message: [AssignedCell<Fp, Fp>; 3],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let chip = Pow5Chip::construct(cfg.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init"),
    )?;
    hasher.hash(layouter.namespace(|| "hash"), message)
}

// ---------- the circuit ----------

/// Private: secret, value, siblings, bits.
/// Public (instance rows): 0 = root, 1 = badge_type, 2 = threshold, 3 = scope, 4 = nullifier.
#[derive(Clone, Default)]
pub struct BadgeCircuit {
    pub secret: Value<Fp>,
    pub badge_type: Value<Fp>,
    pub scope: Value<Fp>,
    pub value: Value<u64>,
    pub threshold: Value<u64>,
    pub siblings: [Value<Fp>; DEPTH],
    pub bits: [Value<Fp>; DEPTH],
}

#[derive(Clone)]
pub struct BadgeConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    state: [Column<Advice>; 3],
    // Merkle swap step
    cur: Column<Advice>,
    sib: Column<Advice>,
    bit: Column<Advice>,
    left: Column<Advice>,
    right: Column<Advice>,
    s_swap: Selector,
    // Threshold range check
    value: Column<Advice>,
    threshold: Column<Advice>,
    diff: Column<Advice>,
    tbit: Column<Advice>,
    acc: Column<Advice>,
    s_diff: Selector,
    s_bit: Selector,
    s_acc: Selector,
    s_first: Selector,
    instance: Column<Instance>,
}

impl Circuit<Fp> for BadgeCircuit {
    type Config = BadgeConfig;
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

        // Merkle swap columns.
        let cur = meta.advice_column();
        let sib = meta.advice_column();
        let bit = meta.advice_column();
        let left = meta.advice_column();
        let right = meta.advice_column();
        let s_swap = meta.selector();

        // Threshold columns.
        let value = meta.advice_column();
        let threshold = meta.advice_column();
        let diff = meta.advice_column();
        let tbit = meta.advice_column();
        let acc = meta.advice_column();
        let s_diff = meta.selector();
        let s_bit = meta.selector();
        let s_acc = meta.selector();
        let s_first = meta.selector();

        let instance = meta.instance_column();

        meta.enable_equality(cur);
        meta.enable_equality(left);
        meta.enable_equality(right);
        meta.enable_equality(value);
        meta.enable_equality(threshold);
        meta.enable_equality(diff);
        meta.enable_equality(acc);
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
                s.clone() * (q_bit.clone() * (q_bit.clone() - one)),
                s.clone()
                    * (q_left
                        - (q_cur.clone() + q_bit.clone() * (q_sib.clone() - q_cur.clone()))),
                s * (q_right - (q_sib.clone() + q_bit * (q_cur - q_sib))),
            ]
        });

        meta.create_gate("diff = value - threshold", |meta| {
            let s = meta.query_selector(s_diff);
            let v = meta.query_advice(value, Rotation::cur());
            let t = meta.query_advice(threshold, Rotation::cur());
            let d = meta.query_advice(diff, Rotation::cur());
            vec![s * (v - t - d)]
        });

        meta.create_gate("threshold bit is boolean", |meta| {
            let s = meta.query_selector(s_bit);
            let b = meta.query_advice(tbit, Rotation::cur());
            vec![s * (b.clone() * (b - Expression::Constant(Fp::from(1u64))))]
        });

        meta.create_gate("accumulate bits", |meta| {
            let s = meta.query_selector(s_acc);
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_next = meta.query_advice(acc, Rotation::next());
            let b = meta.query_advice(tbit, Rotation::cur());
            let two = Expression::Constant(Fp::from(2u64));
            vec![s * (acc_next - (two * acc_cur + b))]
        });

        meta.create_gate("accumulator starts at zero", |meta| {
            let s = meta.query_selector(s_first);
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            vec![s * acc_cur]
        });

        BadgeConfig {
            poseidon,
            state,
            cur,
            sib,
            bit,
            left,
            right,
            s_swap,
            value,
            threshold,
            diff,
            tbit,
            acc,
            s_diff,
            s_bit,
            s_acc,
            s_first,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let pcfg = config.poseidon.clone();

        // Load the private values secret, badge_type, value.
        let loaded: [AssignedCell<Fp, Fp>; 3] = layouter.assign_region(
            || "load private values",
            |mut region| {
                let vals = [self.secret, self.badge_type, self.value.map(Fp::from)];
                let cells: Result<Vec<_>, Error> = vals
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        region.assign_advice(
                            || format!("private_{i}"),
                            config.state[i],
                            0,
                            || *v,
                        )
                    })
                    .collect();
                Ok(cells?.try_into().unwrap())
            },
        )?;
        let [secret_c, badge_c, value_c] = loaded;

        let scope_c = layouter.assign_region(
            || "load scope",
            |mut region| region.assign_advice(|| "scope", config.state[0], 0, || self.scope),
        )?;

        // 1. id = Poseidon(secret)
        let id = hash1c(&pcfg, layouter.namespace(|| "identity"), [secret_c.clone()])?;

        // 2. leaf = Poseidon(id, badge_type, value)
        let leaf = hash3c(
            &pcfg,
            layouter.namespace(|| "leaf"),
            [id, badge_c.clone(), value_c.clone()],
        )?;

        // 3. Merkle path from the leaf up to the root.
        let mut current = leaf;
        for level in 0..DEPTH {
            let (left, right) = layouter.assign_region(
                || format!("swap_{level}"),
                |mut region| {
                    config.s_swap.enable(&mut region, 0)?;

                    let cur_v: Value<Fp> = current.value().copied();
                    let sib_v = self.siblings[level];
                    let bit_v = self.bits[level];

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

            current = hash2c(
                &pcfg,
                layouter.namespace(|| format!("merkle_hash_{level}")),
                [left, right],
            )?;
        }
        let root = current;

        // 4. value >= threshold, using the SAME value that is inside the leaf.
        let thr_cell = layouter.assign_region(
            || "threshold check",
            |mut region| {
                config.s_diff.enable(&mut region, 0)?;
                config.s_first.enable(&mut region, 0)?;

                let value_f = self.value.map(Fp::from);
                let thr_f = self.threshold.map(Fp::from);

                let value_cell =
                    region.assign_advice(|| "value", config.value, 0, || value_f)?;
                // Tie this value to the one hashed into the leaf.
                region.constrain_equal(value_cell.cell(), value_c.cell())?;

                let thr_cell =
                    region.assign_advice(|| "threshold", config.threshold, 0, || thr_f)?;
                let diff_cell =
                    region.assign_advice(|| "diff", config.diff, 0, || value_f - thr_f)?;

                // Honest witness: the 64 bits of (value - threshold).
                // If value < threshold this wraps around and the check below fails.
                let d: Value<u64> = self
                    .value
                    .zip(self.threshold)
                    .map(|(v, t)| v.wrapping_sub(t));

                for i in 0..RANGE_BITS {
                    config.s_bit.enable(&mut region, i)?;
                    config.s_acc.enable(&mut region, i)?;

                    let bit_val = d.map(|d| Fp::from((d >> (RANGE_BITS - 1 - i)) & 1));
                    region.assign_advice(|| format!("tbit_{i}"), config.tbit, i, || bit_val)?;

                    let acc_val = d.map(|d| {
                        if i == 0 {
                            Fp::from(0u64)
                        } else {
                            Fp::from(d >> (RANGE_BITS - i))
                        }
                    });
                    region.assign_advice(|| format!("acc_{i}"), config.acc, i, || acc_val)?;
                }

                let acc_final = region.assign_advice(
                    || "acc_final",
                    config.acc,
                    RANGE_BITS,
                    || d.map(Fp::from),
                )?;
                region.constrain_equal(diff_cell.cell(), acc_final.cell())?;

                Ok(thr_cell)
            },
        )?;

        // 5. nullifier = Poseidon(secret, badge_type, scope)
        let nullifier = hash3c(
            &pcfg,
            layouter.namespace(|| "nullifier"),
            [secret_c, badge_c.clone(), scope_c.clone()],
        )?;

        // Public inputs.
        layouter.constrain_instance(root.cell(), config.instance, 0)?;
        layouter.constrain_instance(badge_c.cell(), config.instance, 1)?;
        layouter.constrain_instance(thr_cell.cell(), config.instance, 2)?;
        layouter.constrain_instance(scope_c.cell(), config.instance, 3)?;
        layouter.constrain_instance(nullifier.cell(), config.instance, 4)
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

    const INDEX: usize = 5;
    const SECRET: u64 = 12345;
    const BADGE: u64 = 1;
    const VALUE: u64 = 750;

    struct Fixture {
        root: Fp,
        siblings: [Fp; DEPTH],
        bits: [Fp; DEPTH],
    }

    /// An issuer tree of 16 credentials. Slot INDEX belongs to our holder.
    fn fixture() -> Fixture {
        let badge = Fp::from(BADGE);
        let leaves: Vec<Fp> = (0..(1usize << DEPTH))
            .map(|i| {
                if i == INDEX {
                    leaf_of(identity(Fp::from(SECRET)), badge, VALUE)
                } else {
                    leaf_of(identity(Fp::from(7000 + i as u64)), badge, 100 + i as u64)
                }
            })
            .collect();
        let (root, siblings, bits) = root_and_path(&leaves, INDEX);
        Fixture { root, siblings, bits }
    }

    fn circuit(f: &Fixture, secret: u64, value: u64, threshold: u64, scope: u64) -> BadgeCircuit {
        BadgeCircuit {
            secret: Value::known(Fp::from(secret)),
            badge_type: Value::known(Fp::from(BADGE)),
            scope: Value::known(Fp::from(scope)),
            value: Value::known(value),
            threshold: Value::known(threshold),
            siblings: f.siblings.map(Value::known),
            bits: f.bits.map(Value::known),
        }
    }

    fn public(f: &Fixture, threshold: u64, scope: u64) -> Vec<Fp> {
        let nf = nullifier_of(Fp::from(SECRET), Fp::from(BADGE), Fp::from(scope));
        vec![
            f.root,
            Fp::from(BADGE),
            Fp::from(threshold),
            Fp::from(scope),
            nf,
        ]
    }

    #[test]
    fn badge_accepts_honest_holder() {
        let f = fixture();
        let c = circuit(&f, SECRET, VALUE, 500, 99);
        let prover = MockProver::run(K, &c, vec![public(&f, 500, 99)]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn badge_rejects_value_below_threshold() {
        let f = fixture();
        // Value 750 is below threshold 800.
        let c = circuit(&f, SECRET, VALUE, 800, 99);
        let prover = MockProver::run(K, &c, vec![public(&f, 800, 99)]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn badge_rejects_inflated_value() {
        let f = fixture();
        // Claims value 900 but the issuer signed 750 into the leaf.
        let c = circuit(&f, SECRET, 900, 800, 99);
        let prover = MockProver::run(K, &c, vec![public(&f, 800, 99)]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn badge_rejects_someone_elses_secret() {
        let f = fixture();
        // A different secret cannot open this holder's leaf.
        let c = circuit(&f, 99999, VALUE, 500, 99);
        let prover = MockProver::run(K, &c, vec![public(&f, 500, 99)]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn badge_rejects_wrong_nullifier() {
        let f = fixture();
        let c = circuit(&f, SECRET, VALUE, 500, 99);
        let mut inst = public(&f, 500, 99);
        inst[4] += Fp::from(1u64);
        let prover = MockProver::run(K, &c, vec![inst]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn badge_rejects_wrong_public_threshold() {
        let f = fixture();
        let c = circuit(&f, SECRET, VALUE, 500, 99);
        let prover = MockProver::run(K, &c, vec![public(&f, 600, 99)]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn badge_nullifier_depends_on_scope() {
        let a = nullifier_of(Fp::from(SECRET), Fp::from(BADGE), Fp::from(99u64));
        let a2 = nullifier_of(Fp::from(SECRET), Fp::from(BADGE), Fp::from(99u64));
        let b = nullifier_of(Fp::from(SECRET), Fp::from(BADGE), Fp::from(100u64));
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn badge_real_proof_roundtrip() {
        let f = fixture();
        let inst = public(&f, 500, 99);
        let c = circuit(&f, SECRET, VALUE, 500, 99);

        let t = Instant::now();
        let params: Params<EqAffine> = Params::new(K);
        let empty = BadgeCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("keygen_pk");
        println!("badge setup + keygen: {:?}", t.elapsed());

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
            "badge prove: {:?}, proof size: {} bytes",
            t.elapsed(),
            proof.len()
        );

        let t = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&inst[..]]], &mut transcript).is_ok()
        );
        println!("badge verify: {:?}", t.elapsed());

        // The same proof claimed for a different scope: rejected.
        let wrong = public(&f, 500, 100);
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&wrong[..]]], &mut transcript)
                .is_err()
        );
    }
}
