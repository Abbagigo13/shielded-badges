use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

/// Private inputs: a and b. Public input: c = a * b.
#[derive(Clone, Default)]
pub struct MulCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

#[derive(Clone, Debug)]
pub struct MulConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    s: Selector,
    instance: Column<Instance>,
}

impl Circuit<Fp> for MulCircuit {
    type Config = MulConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let instance = meta.instance_column();
        let s = meta.selector();

        meta.enable_equality(c);
        meta.enable_equality(instance);

        // The rule: when the selector is on, a * b - c must equal 0.
        meta.create_gate("a * b = c", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let s = meta.query_selector(s);
            vec![s * (a * b - c)]
        });

        MulConfig { a, b, c, s, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let c_cell = layouter.assign_region(
            || "multiply",
            |mut region| {
                config.s.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.a, 0, || self.a)?;
                region.assign_advice(|| "b", config.b, 0, || self.b)?;
                region.assign_advice(|| "c = a * b", config.c, 0, || self.a * self.b)
            },
        )?;

        // Make c the public input.
        layouter.constrain_instance(c_cell.cell(), config.instance, 0)
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

    const K: u32 = 5;

    #[test]
    fn mock_prover_accepts_good_and_rejects_bad() {
        let a = Fp::from(6);
        let b = Fp::from(7);
        let circuit = MulCircuit { a: Value::known(a), b: Value::known(b) };

        let good = MockProver::run(K, &circuit, vec![vec![Fp::from(42)]]).unwrap();
        assert_eq!(good.verify(), Ok(()));

        let bad = MockProver::run(K, &circuit, vec![vec![Fp::from(43)]]).unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn real_proof_roundtrip() {
        let a = Fp::from(6);
        let b = Fp::from(7);
        let c = Fp::from(42);
        let circuit = MulCircuit { a: Value::known(a), b: Value::known(b) };

        // Setup
        let params: Params<EqAffine> = Params::new(K);
        let empty = MulCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("keygen_pk");

        // Prove
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&[c]]],
            UnwrapErr(SysRng),
            &mut transcript,
        )
        .expect("proof generation");
        let proof: Vec<u8> = transcript.finalize();
        println!("proof size: {} bytes", proof.len());

        // Verify with the right public value
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[&[c]]], &mut transcript).is_ok());

        // Verify with a wrong public value: must fail
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let wrong = Fp::from(43);
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[&[wrong]]], &mut transcript).is_err());
    }
}
