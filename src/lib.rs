#![doc = include_str!("../README.md")]

use chrono::TimeDelta;
use twine_protocol::{prelude::*, twine_lib::{ipld_core::serde::from_ipld, multihash_codetable::{Code, Multihash}, semver::VersionReq}};

mod payload;
pub use payload::*;

mod timing;
pub use timing::*;

mod validations;

/// The prefix for the twine-rng specification
pub const SPEC_PREFIX : &str = "twine-rng";
/// The current version of the twine-rng specification
pub const SPEC_VERSION : &str = "1.0.0";

/// The spec string to use when building a strand
pub fn subspec_string() -> String {
  format!("{}/{}", SPEC_PREFIX, SPEC_VERSION)
}

/// The strand details for the twine-rng specification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RngStrandDetails {
  pub period: TimeDelta,
}

/// A builder to aid in constructing payloads for the twine-rng specification
///
/// # Example
///
/// ```
/// use twine_spec_rng::PayloadBuilder;
/// let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());
/// // use in the tixel builder
/// // `.build_payload_then_done(pb.builder())`
/// // then advance the payload with new randomness
/// let pb = pb.advance([2u8; 32].to_vec());
/// ```
pub struct PayloadBuilder {
  current: Vec<u8>,
  next: Vec<u8>,
}

impl PayloadBuilder {
  /// Create a new payload builder
  ///
  /// When starting from the beginning of a strand, the `current` value will be ignored
  pub fn new(current: Vec<u8>, next: Vec<u8>) -> Self {
    Self { current, next }
  }

  pub fn current(&self) -> &[u8] {
    &self.current
  }

  pub fn pre(&self, code: Code) -> Multihash {
    use twine_protocol::twine_lib::multihash_codetable::MultihashDigest;
    code.digest(&self.next)
  }

  pub fn advance(self, next: Vec<u8>) -> Self {
    Self::new(self.next, next)
  }

  pub fn builder(&self) -> impl Fn(&Strand, Option<&Twine>) -> Result<RandomnessPayload, BuildError> + '_ {
    move |strand: &Strand, prev: Option<&Twine>| {
      validations::validate_signing_algorithm(strand.key().alg)?;
      let subspec = strand.subspec().ok_or(BuildError::PayloadConstruction("Subspec is required for validation".to_string()))?;
      validations::validate_subspec(&subspec)?;

      if !subspec.satisfies(VersionReq::parse("1.0.*").unwrap()) {
        return Err(BuildError::BadData(VerificationError::Payload("Unable to build payload for future version".to_string())));
      }

      let details: RngStrandDetails = from_ipld(strand.details().clone())
        .map_err(|_| BuildError::BadData(VerificationError::Payload("Invalid strand details".to_string())))?;
      let period = details.period;

      let pre = self.pre(strand.hasher());

      match prev {
        None => {
          let payload = RandomnessPayload::new_start(pre, period)?;
          Ok(payload)
        }
        Some(prev) => {
          let payload = RandomnessPayload::new_next(self.current(), pre, prev.tixel(), period)?;
          Ok(payload)
        }
      }
    }
  }
}

/// Safely extract the randomness from a twine pair
///
/// This function performs necessary validations to ensure the randomness is valid
pub fn extract_randomness(
  current: &Twine,
  prev: &Twine,
) -> Result<Vec<u8>, VerificationError> {
  if current.strand_cid() != prev.strand_cid() {
    return Err(VerificationError::General(
      "Current tixel and previous tixel are on different strands".to_string(),
    ));
  }
  match current.previous() {
    None => {
      return Err(VerificationError::General(
        "Current tixel has no previous link".to_string(),
      ));
    }
    Some(p) => {
      if prev != &p {
        return Err(VerificationError::General(
          "Previous tixel does not match current tixel's previous link".to_string(),
        ));
      }
    }
  };

  let payload = current.extract_payload::<RandomnessPayload>()?;
  if let Err(e) = payload.validate_randomness(prev) {
    return Err(e);
  }
  Ok(current.cid().hash().digest().to_vec())
}

#[cfg(test)]
mod test {
  use twine_protocol::twine_builder::RingSigner;
  use crate::*;

  fn builder() -> (TwineBuilder<2, RingSigner>, Strand) {
    let signer = RingSigner::generate_rs256(2048).unwrap();
    let builder = TwineBuilder::new(signer);
    let strand = builder.build_strand()
      .subspec(subspec_string())
      .hasher(Code::Sha3_256)
      .details(RngStrandDetails { period: TimeDelta::seconds(60) })
      .done()
      .unwrap();

    (builder, strand)
  }

  #[test]
  fn test_builder() {
    let (builder, strand) = builder();
    let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());

    let first = builder.build_first(strand)
      .build_payload_then_done(pb.builder())
      .unwrap();

    let pb = pb.advance([2u8; 32].to_vec());

    let second = builder.build_next(&first)
      .build_payload_then_done(pb.builder())
      .unwrap();

    // println!("First: {}", first);
    // println!("Second: {}", second);

    let first_payload = first.extract_payload::<RandomnessPayload>().unwrap();
    assert_eq!(first_payload.salt(), vec![0u8; 32]);

    let second_payload = second.extract_payload::<RandomnessPayload>().unwrap();
    assert_eq!(second_payload.local_random_value(&first), vec![1u8; 32]);

    let payload = second.extract_payload::<RandomnessPayload>().unwrap();
    payload.validate_randomness(&first).unwrap();
  }

  #[test]
  fn test_bad_construction() {
    let (builder, strand) = builder();
    let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());

    let first = builder.build_first(strand)
      .build_payload_then_done(pb.builder())
      .unwrap();

    // oops
    assert!(builder.build_next(&first)
      .build_payload_then_done(pb.builder())
      .is_err());

    // oops again
    let pb = pb.advance([2u8; 32].to_vec()).advance([3u8; 32].to_vec());

    assert!(builder.build_next(&first)
      .build_payload_then_done(pb.builder())
      .is_err());
  }

  #[test]
  fn test_frayed_strand(){
    let (builder, strand) = builder();
    let pb1 = PayloadBuilder::new([0u8; 32].to_vec(), [11u8; 32].to_vec());
    let first_1 = builder.build_first(strand.clone())
      .build_payload_then_done(pb1.builder())
      .unwrap();

    let pb1 = pb1.advance([12u8; 32].to_vec());

    let second_1 = builder.build_next(&first_1)
      .build_payload_then_done(pb1.builder())
      .unwrap();

    let pb2 = PayloadBuilder::new([0u8; 32].to_vec(), [12u8; 32].to_vec());
    let first_2 = builder.build_first(strand)
      .build_payload_then_done(pb2.builder())
      .unwrap();

    let pb2 = pb2.advance([22u8; 32].to_vec());

    let second_2 = builder.build_next(&first_2)
      .build_payload_then_done(pb2.builder())
      .unwrap();

    assert!(extract_randomness(&second_2, &first_1).is_err());
    assert!(extract_randomness(&second_1, &first_2).is_err());
  }

  #[test]
  fn test_reject_bad_signing_key() {
    let signer = RingSigner::generate_ed25519().unwrap();
    let builder = TwineBuilder::new(signer);
    let strand = builder.build_strand()
      .subspec(subspec_string())
      .hasher(Code::Sha3_256)
      .details(RngStrandDetails { period: TimeDelta::seconds(60) })
      .done()
      .unwrap();

    let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());

    assert!(builder.build_first(strand)
      .build_payload_then_done(pb.builder())
      .is_err());
  }

  #[test]
  fn test_reject_late_pulse() {
    let signer = RingSigner::generate_rs256(2048).unwrap();
    let builder = TwineBuilder::new(signer);
    let strand = builder.build_strand()
      .subspec(subspec_string())
      .hasher(Code::Sha3_256)
      .details(RngStrandDetails { period: TimeDelta::seconds(60) })
      .done()
      .unwrap();

    let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());

    let first = builder.build_first(strand)
      .build_payload_then_done(pb.builder())
      .unwrap();

    let pb = pb.advance([2u8; 32].to_vec());

    let payload = pb.builder()(&first.strand(), Some(&first)).unwrap();
    let salt = payload.salt();
    let pre = payload.pre().clone();
    let timestamp = next_pulse_timestamp(payload.timestamp(), TimeDelta::seconds(60));
    let late_payload = RandomnessPayload::try_new(salt.into(), pre, timestamp).unwrap();

    let second = builder.build_next(&first)
      .payload(late_payload)
      .done()
      .unwrap();

    let ret = extract_randomness(&second, &first);
    dbg!(&ret);
    assert!(ret.is_err(), "Should reject late pulse");
  }
}