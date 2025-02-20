//! Hash functions. For further documentation please refer to rust_symcrypt::hash
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use symcrypt::hash::{sha256, sha384, HashState, Sha256State, Sha384State};

// ShaXXX is a struct that represents either a Sha256 or Sha384 hash Algorithm
//
// ShaXXXContext is a wrapper over the ShaXXXState from SymCrypt. This is what needs to
// be initialized in order to run stateful operations on the SymCrypt ShaXXXState.
//
//
//
// Impl's for the Hash trait for both Sha256 and Sha384 implement the Ruslts traits for hashing
//
// `algorithm()` returns Rustls' friendly [`HashAlgorithm`] name
//
// `output_len()` returns the output length for ShaXXX
//
// `start()` creates a `Box<>'d` ShaXXXContext that is needed in order to run stateful operations
//
// `hash()` computes a stateless hash operation based on the current ShaXXX hash algorithm.
//
//
//
// Impl's for the Context trait for both [`Sha256Context`] and [`Sha384Context`] implement the Rustls trait for
// hashing context which is called state on the SymCrypt side.
//
// `fork_finish()` creates clones of the current hash state and then returns the clone'd hash result
// There is no intermediate fork operation like this for this native to SymCrypt so a clone must be created.
//
// `fork()` creates a new ShaXXXContext that is a clone of the current Hash state
//
// `finish()` returns the hash output for the current ShaXXXContext. This results in the end of lifetime for the ShaXXXContext and therefore is
// the end of life for ShaXXXState. `SymCryptWipe()` will be called under the covers.
//
// `update()` appends data to the ShaXXXState in order to be hashed. This operation can be done multiple times.


/// Structs related to Sha256
pub struct Sha256;
pub struct Sha256Context(Sha256State);

/// Structs related to Sha384
pub struct Sha384;
struct Sha384Context(Sha384State);

/// Impl's for Sha256 related traits
impl Hash for Sha256 {
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn output_len(&self) -> usize {
        32
    }

    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(Sha256State::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&sha256(data)[..])
    }
}

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        let mut new_context = self.0.clone();

        Output::new(&new_context.result()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> Output {
        Output::new(&self.0.result()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.append(data);
    }
}

/// Impl's for Sha384 related traits
impl Hash for Sha384 {
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }

    fn output_len(&self) -> usize {
        48
    }

    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(Sha384State::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&sha384(data)[..])
    }
}

impl Context for Sha384Context {
    fn fork_finish(&self) -> Output {
        let mut new_context = self.0.clone();
        Output::new(&new_context.result()[..])
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Sha384Context(self.0.clone()))
    }

    fn finish(mut self: Box<Self>) -> Output {
        Output::new(&self.0.result()[..])
    }

    fn update(&mut self, data: &[u8]) {
        self.0.append(data);
    }
}
