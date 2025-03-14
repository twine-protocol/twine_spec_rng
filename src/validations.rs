use twine_protocol::{prelude::BuildError, twine_lib::{crypto::SignatureAlgorithm, specification::Subspec}};

pub fn validate_signing_algorithm(alg: SignatureAlgorithm) -> Result<(), BuildError> {
  match alg {
    SignatureAlgorithm::Sha256Rsa(_) => Ok(()),
    SignatureAlgorithm::Sha384Rsa(_) => Ok(()),
    SignatureAlgorithm::Sha512Rsa(_) => Ok(()),
    _ => Err(BuildError::PayloadConstruction("Signature algorithm must be provably deterministic".to_string())),
  }
}

pub fn validate_subspec(subspec: &Subspec) -> Result<(), BuildError> {
  if subspec.prefix() != crate::SPEC_PREFIX {
    return Err(BuildError::PayloadConstruction(format!(
      "Subspec prefix must be {}",
      crate::SPEC_PREFIX
    )));
  }
  Ok(())
}