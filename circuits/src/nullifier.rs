use halo2_gadgets::poseidon::primitives as poseidon;
use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};

/// Rows in the circuit: 2^K. A 3-input Poseidon needs K = 7.
pub const K: u32 = 7;

/// nullifier = Poseidon(secret, badge_type, scope), computed outside the circuit.
/// Used to produce the expected public value and to cross-check the circuit.
pub fn native_nullifier(secret: Fp, badge_type: Fp, scope: Fp) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init()
        .hash([secret, badge_type, scope])
}

/// Private input: secret.
/// Public inputs (instance rows): 0 = badge_type, 1 = scope, 2 = nullifier.
#[derive(Clone, Default)]
pub struct NullifierCircuit {
    pub secret: Value<Fp>,
    pub badge_type: Value<Fp>,
    pub scope: Value<Fp>,
}

#[derive(Clone)]
pub struct NullifierConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    // Our own copy of the Poseidon state columns (the library keeps its copy private).
    state: [Column<Advice>; 3],
    instance: Column<Instance>,
}

impl Circuit<Fp> for NullifierCircuit {
    type Config = NullifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state: [Column<Advice>; 3] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let partial_sbox = meta.advice_column();
        let rc_a: Vec<_> = (0..3).map(|_| meta.fixed_column()).collect();
        let rc_b: Vec<_> = (0..3).map(|_| meta.fixed_column()).collect();

        // The Poseidon padding needs a constants column.
        meta.enable_constant(rc_b[0]);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let poseidon: Pow5Config<Fp, 3, 2> = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        NullifierConfig {
            poseidon,
            state,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon.clone());

        // Load the three inputs into the Poseidon state columns.
        let values = [self.secret, self.badge_type, self.scope];
        let message: [AssignedCell<Fp, Fp>; 3] = layouter.assign_region(
            || "load inputs",
            |mut region| {
                let cells: Result<Vec<_>, Error> = values
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        region.assign_advice(
                            || format!("input_{i}"),
                            config.state[i],
                            0,
                            || *v,
                        )
                    })
                    .collect();
                Ok(cells?.try_into().unwrap())
            },
        )?;

        // nullifier = Poseidon(secret, badge_type, scope)
        let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<3>, 3, 2>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let nullifier = hasher.hash(layouter.namespace(|| "hash"), message.clone())?;

        // Expose badge_type, scope and nullifier as public inputs.
        layouter.constrain_instance(message[1].cell(), config.instance, 0)?;
        layouter.constrain_instance(message[2].cell(), config.instance, 1)?;
        layouter.constrain_instance(nullifier.cell(), config.instance, 2)
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

    fn make_circuit(secret: Fp, badge_type: Fp, scope: Fp) -> NullifierCircuit {
        NullifierCircuit {
            secret: Value::known(secret),
            badge_type: Value::known(badge_type),
            scope: Value::known(scope),
        }
    }

    #[test]
    fn circuit_matches_native_hash() {
        let secret = Fp::from(12345u64);
        let badge_type = Fp::from(1u64);
        let scope = Fp::from(99u64);
        let nf = native_nullifier(secret, badge_type, scope);

        let circuit = make_circuit(secret, badge_type, scope);

        let good = MockProver::run(K, &circuit, vec![vec![badge_type, scope, nf]]).unwrap();
        assert_eq!(good.verify(), Ok(()));

        let wrong_nf = nf + Fp::from(1u64);
        let bad = MockProver::run(K, &circuit, vec![vec![badge_type, scope, wrong_nf]]).unwrap();
        assert!(bad.verify().is_err());
    }

    #[test]
    fn scope_changes_nullifier() {
        let secret = Fp::from(12345u64);
        let badge_type = Fp::from(1u64);

        let a = native_nullifier(secret, badge_type, Fp::from(99u64));
        let a_again = native_nullifier(secret, badge_type, Fp::from(99u64));
        let b = native_nullifier(secret, badge_type, Fp::from(100u64));

        assert_eq!(a, a_again, "same scope must give the same nullifier");
        assert_ne!(a, b, "different scopes must give different nullifiers");
    }

    #[test]
    fn real_proof_roundtrip() {
        let secret = Fp::from(12345u64);
        let badge_type = Fp::from(1u64);
        let scope = Fp::from(99u64);
        let nf = native_nullifier(secret, badge_type, scope);
        let inst = [badge_type, scope, nf];

        let circuit = make_circuit(secret, badge_type, scope);

        let t = Instant::now();
        let params: Params<EqAffine> = Params::new(K);
        let empty = NullifierCircuit::default();
        let vk = keygen_vk(&params, &empty).expect("keygen_vk");
        let pk = keygen_pk(&params, vk, &empty).expect("keygen_pk");
        println!("setup + keygen: {:?}", t.elapsed());

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
        println!("prove: {:?}, proof size: {} bytes", t.elapsed(), proof.len());

        // Right public inputs: accepted.
        let t = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&inst[..]]], &mut transcript).is_ok()
        );
        println!("verify: {:?}", t.elapsed());

        // Same proof claimed for a different scope: rejected.
        let wrong = [badge_type, Fp::from(100u64), nf];
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            verify_proof(&params, pk.get_vk(), strategy, &[&[&wrong[..]]], &mut transcript)
                .is_err()
        );
    }
}
