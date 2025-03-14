use chrono::TimeDelta;
use twine_protocol::prelude::*;
use twine_protocol::twine_lib::multihash_codetable::Code;
use twine_protocol::twine_lib::multihash_codetable::Multihash;
use twine_protocol::twine_lib::verify::{Verifiable, Verified};
use twine_protocol::twine_lib::Bytes;

use crate::RngStrandDetails;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RandomnessPayloadRaw {
  salt: Bytes,
  pre: Multihash,
  timestamp: chrono::DateTime<chrono::Utc>,
}

impl Verifiable for RandomnessPayloadRaw {
  fn verify(&self) -> Result<(), VerificationError> {
    if self.salt.len() != self.pre.size() as usize {
      return Err(VerificationError::Payload(
        "Salt length does not match pre hash size".to_string(),
      ));
    }
    // verify that the timestamp doesn't have any ms
    if self.timestamp.timestamp_subsec_millis() != 0 {
      return Err(VerificationError::Payload(
        "Timestamp has milliseconds".to_string(),
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RandomnessPayload(Verified<RandomnessPayloadRaw>);

impl RandomnessPayload {
  pub fn try_new(
    salt: Bytes,
    pre: Multihash,
    timestamp: chrono::DateTime<chrono::Utc>,
  ) -> Result<Self, VerificationError> {
    Verified::try_new(RandomnessPayloadRaw {
      salt,
      pre,
      timestamp,
    })
    .map(Self)
  }

  pub fn new_next(
    rand: &[u8],
    pre: Multihash,
    prev: &Tixel,
    period: chrono::TimeDelta,
  ) -> Result<Self, BuildError> {
    // ensure rand corresponds to previous pre
    let prev_payload = prev.extract_payload::<RandomnessPayload>()?;

    let hasher = prev.hasher();
    use twine_protocol::twine_lib::multihash_codetable::MultihashDigest;
    if prev_payload.0.pre != hasher.digest(&rand) {
      return Err(BuildError::PayloadConstruction(
        "Precommitment does not match random bytes".to_string(),
      ));
    }

    if prev.cid().hash().size() != pre.size() {
      return Err(BuildError::PayloadConstruction(
        "Pre hash size does not match previous tixel hash size".to_string(),
      ));
    }
    // we xor the random bytes with previous cid hash digest
    let salt = Bytes(
      rand
        .iter()
        .zip(prev.cid().hash().digest().iter())
        .map(|(a, b)| a ^ b)
        .collect(),
    );
    let timestamp =
      crate::timing::next_pulse_timestamp(prev_payload.0.timestamp, period);
    Ok(Self::try_new(salt, pre, timestamp)?)
  }

  pub fn new_start(
    pre: Multihash,
    period: TimeDelta,
  ) -> Result<Self, VerificationError> {
    let num_bytes = pre.size() as usize;
    let salt = Bytes(vec![0u8; num_bytes]);
    let timestamp = crate::timing::next_truncated_time(period);
    Self::try_new(salt, pre, timestamp)
  }

  pub fn validate_randomness(
    &self,
    prev: &Twine,
  ) -> Result<(), VerificationError> {
    if prev.cid().hash().size() != self.0.pre.size() {
      return Err(VerificationError::Payload(
        "Pre hash size does not match previous tixel hash size".to_string(),
      ));
    }
    let prev_payload = prev.extract_payload::<RandomnessPayload>()?;
    if self.0.timestamp < prev_payload.0.timestamp {
      return Err(VerificationError::Payload(
        "Timestamp is less than previous tixel timestamp".to_string(),
      ));
    }
    // ensure it's within the period
    let period = prev.strand().extract_details::<RngStrandDetails>()?.period;
    if (self.0.timestamp - prev_payload.0.timestamp) != period {
      return Err(VerificationError::Payload(
        "Timestamps are not within one period of each other".to_string(),
      ));
    }

    // check that the precommitment from the previous tixel matches the xor rand value
    let rand = self.local_random_value(prev);

    use twine_protocol::twine_lib::multihash_codetable::MultihashDigest;
    let code = Code::try_from(prev_payload.pre().code())
      .map_err(|_| VerificationError::UnsupportedHashAlgorithm)?;
    let pre = code.digest(&rand);

    if &pre != prev_payload.pre() {
      return Err(VerificationError::Payload(
        "Previous tixel pre hash does not match hash of random value".to_string(),
      ));
    }
    Ok(())
  }

  pub fn local_random_value(&self, prev: &Twine) -> Vec<u8> {
    self
      .salt()
      .iter()
      .zip(prev.cid().hash().digest().iter())
      .map(|(a, b)| a ^ b)
      .collect::<Vec<u8>>()
  }

  pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
    self.0.timestamp
  }

  pub fn salt(&self) -> &[u8] {
    &self.0.salt.0
  }

  pub fn pre(&self) -> &Multihash {
    &self.0.pre
  }
}


#[cfg(test)]
mod test {
  use crate::RngStrandDetails;
  use super::*;
  use twine_protocol::{twine_builder::RingSigner, twine_lib::serde_ipld_dagjson};

  fn valid() -> &'static str {
    r#"{
      "salt": {
        "/": {
          "bytes": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw"
        }
      },
      "pre": {
        "/": {
          "bytes": "FEBbiyt/CsvMESCWmLtqDl4m1hyKq7/zK5nFsyJjALZNyL99pez/is7BCSHXYkW1YjreW2KWA04zJrhD4Jjcx6b6"
        }
      },
      "timestamp": "2025-02-12T21:11:00Z"
    }"#
  }

  #[test]
  fn test_deserialize() {
    let ret: Result<RandomnessPayload, _> = serde_ipld_dagjson::from_slice(valid().as_bytes());
    assert!(ret.is_ok(), "Deserialization failed {:?}", ret);

    let invalid_ts = r#"{
      "salt": {
        "/": {
          "bytes": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw"
        }
      },
      "pre": {
        "/": {
          "bytes": "FEBbiyt/CsvMESCWmLtqDl4m1hyKq7/zK5nFsyJjALZNyL99pez/is7BCSHXYkW1YjreW2KWA04zJrhD4Jjcx6b6"
        }
      },
      "timestamp": "2025-02-12T21:11:00.01Z"
    }"#;


    let ret: Result<RandomnessPayload, _> = serde_ipld_dagjson::from_slice(invalid_ts.as_bytes());
    assert!(ret.is_err(), "Deserialization should fail for invalid payload");
  }

  #[test]
  fn test_mallicious_data() {
    let signer = RingSigner::generate_rs256(2048).unwrap();
    let builder = TwineBuilder::new(signer);
    let strand = builder.build_strand()
      .details(RngStrandDetails {
        period: TimeDelta::seconds(60),
      })
      .subspec("twine-rng/1.0.0".into())
      .hasher(Code::Sha3_512)
      .done()
      .unwrap();

    let first = builder.build_first(strand).done().unwrap();
    use twine_protocol::twine_lib::multihash_codetable::MultihashDigest;
    let payload = RandomnessPayload::try_new(
      [22u8; 64].to_vec().into(),
      Code::Sha3_512.digest(&[1u8; 64]),
      chrono::DateTime::parse_from_rfc3339("2025-02-12T21:10:00Z").unwrap().to_utc()
    )
    .unwrap();
    let second = builder.build_next(&first)
      .payload(payload)
      .done()
      .unwrap();

    let valid: RandomnessPayload = serde_ipld_dagjson::from_slice(valid().as_bytes()).unwrap();
    let ret = valid.validate_randomness(&second);
    assert!(ret.is_err(), "Validation should fail for malicious data {:?}", ret);
  }
}