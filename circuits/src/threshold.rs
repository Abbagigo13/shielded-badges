use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

/// Rows in the circuit: 2^K. The range check uses about 65 rows.
pub const K: u32 = 7;

/// diff = value - threshold must fit in this many bits.
pub const RANGE_BITS: usize = 64;

/// Private input: value. Public input (instance row 0): threshold.
/// Proves value >= threshold.
#[derive(Clone, Default)]
pub struct ThresholdCircuit {
    pub value: Value<u64>,
    pub threshold: Value<u64>,
}

#[derive(Clone, Debug)]
pub struct ThresholdConfig {
    value: Column<Advice>,
    threshold: Column<Advice>,
    diff: Column<Advice>,
    bit: Column<Advice>,
    acc: Column<Advice>,
    instance: Column<Instance>,
    s_diff: Selector,
    s_bit: Selector,
    s_acc: Selector,
    s_first: Selector,
}

impl Circuit<Fp> for ThresholdCircuit {
    type Config = ThresholdConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let value = meta.advice_column();
        let threshold = meta.advice_column();
        let diff = meta.advice_column();
        let bit = meta.advice_column();
        let acc = meta.advice_column();
        let instance = meta.instance_column();

        let s_diff = meta.selector();
        let s_bit = meta.selector();
        let s_acc = meta.selector();
        let s_first = meta.selector();

        meta.enable_equality(threshold);
        meta.enable_equality(diff);
        meta.enable_equality(acc);
        meta.enable_equality(instance);

        // diff = value - threshold
        meta.create_gate("diff = value - threshold", |meta| {
            let s = meta.query_selector(s_diff);
            let v = meta.query_advice(value, Rotation::cur());
            let t = meta.query_advice(threshold, Rotation::cur());
            let d = meta.query_advice(diff, Rotation::cur());
            vec![s * (v - t - d)]
        });

        // every bit is 0 or 1
        meta.create_gate("bit is boolean", |meta| {
            let s = meta.query_selector(s_bit);
            let b = meta.query_advice(bit, Rotation::cur());
            vec![s * (b.clone() * (b - Expression::Constant(Fp::from(1u64))))]
        });

        // running total: acc_next = 2 * acc + bit (most significant bit first)
        meta.create_gate("accumulate bits", |meta| {
            let s = meta.query_selector(s_acc);
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_next = meta.query_advice(acc, Rotation::next());
            let b = meta.query_advice(bit, Rotation::cur());
            let two = Expression::Constant(Fp::from(2u64));
            vec![s * (acc_next - (two * acc_cur + b))]
        });

        // the running total starts at zero
        meta.create_gate("accumulator starts at zero", |meta| {
            let s = meta.query_selector(s_first);
            let acc_cur = meta.query_advice(acc, Rotation::cur());
            vec![s * acc_cur]
        });

        ThresholdConfig {
            value,
            threshold,
            diff,
            bit,
            acc,
            instance,
            s_diff,
            s_bit,
            s_acc,
            s_first,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let thr_cell = layouter.assign_region(
            || "threshold check",
            |mut region| {
                config.s_diff.enable(&mut region, 0)?;

                let value_f = self.value.map(Fp::from);
                let thr_f = self.threshold.map(Fp::from);

                region.assign_advice(|| "value", config.value, 0, || value_f)?;
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

                config.s_first.enable(&mut region, 0)?;

                for i in 0..RANGE_BITS {
                    config.s_bit.enable(&mut region, i)?;
                    config.s_acc.enable(&mut region, i)?;

                    let bit_val = d.map(|d| Fp::from((d >> (RANGE_BITS - 1 - i)) & 1));
                    region.assign_advice(|| format!("bit_{i}"), config.bit, i, || bit_val)?;

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

                // The bits must add up to exactly value - threshold.
                region.constrain_equal(diff_cell.cell(), acc_final.cell())?;

                Ok(thr_cell)
            },
        )?;

        // threshold is the public input.
        layouter.constrain_instance(thr_cell.cell(), config.instance, 0)
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

    fn make(value: u64, threshold: u64) -> ThresholdCircuit {
        ThresholdCircuit {
            value: Value::known(value),
            threshold: Value::known(threshold),
        }
    }

    #[test]
    fn accepts_value_at_or_above_threshold() {
        for (v, t) in [(750u64, 500u64), (500, 500), (0, 0), (u64::MAX, 1)] {
            let prover = MockProver::run(K, &make(v, t), vec![vec![Fp::from(t)]]).unwrap();
            assert_eq!(prover.verify(), Ok(()), "value {v}, threshold {t}");
        }
    }

    #[test]
    fn rejects_value_below_threshold() {
        // The cheat: value 400 is below threshold 500, so the difference wraps around.
        let prover = MockProver::run(K, &make(400, 500), vec![vec![Fp::from(500u64)]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn rejects_wrong_public_threshold() {
        // The circuit used threshold 500, but the public input claims 600.
        let prover = MockProver::run(K, &make(750, 500), vec![vec![Fp::from(600u64)]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn real_proof_roundtrip() {
        let inst = [Fp::from(500u64)];
        let circuit = make(750, 500);

        let t = Instant::now();
        let params: Params<EqAffine> = Params::new(K);
        let empty = ThresholdCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("keygen_pk");
        println!("threshold setup + keygen: {:?}", t.elapsed());

        let t = Instant::now();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&inst[..]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .expect("proof generation");
        let proof: Vec<u8> = transcript.finalize();
        println!(
            "threshold prove: {:?}, proof size: {} bytes",
            t.elapsed(),
            proof.len()
        );

        let t = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&inst[..]]], &mut transcript).is_ok()
        );
        println!("threshold verify: {:?}", t.elapsed());

        // The same proof claimed for a different threshold: rejected.
        let wrong = [Fp::from(600u64)];
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&wrong[..]]], &mut transcript)
                .is_err()
        );
    }
}
