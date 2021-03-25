use super::*;
use extensions::ExtensionOutput;
use crypto::ped92::{Commitment, CommitmentProof};
use pairing::Engine;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct Intermediary<E: Engine> {
    invoice: Commitment<E>,
    proof: CommitmentProof<E>
}

impl<E: Engine> ExtensionInit for Intermediary<E> {
    fn init(&self) {}
}

impl<E: Engine> ExtensionOutput for Intermediary<E> {
        fn output(&self) -> Result<String, String> {
        unimplemented!()
    }
}