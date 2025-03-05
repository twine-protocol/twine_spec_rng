# Twine RNG Specification library

This library provides the necessary tools to build and validate
`twine-rng` strands. It is intended to be used with the
[twine-rs](https://github.com/twine-protocol/twine-rs) library.

## Example

Validation of a twine pair:

```rs,ignore
use twine_spec_rng::extract_randomness;

let current: Twine = ...;
let previous: Twine = ...;
let rand = extract_randomness(&current, &previous)?;
```

Building an rng strand.

**Note**: When building, timing is important. When the payload
is built, it calculates the timestamp that the next tixel should
be available. If it's late and takes longer to create than the period,
the randomness extraction will fail when a client attempts to extract
it.

```rs
use twine::{twine_builder::{RingSigner, TwineBuilder}, twine_core::crypto::PublicKey};
use chrono::TimeDelta;
use twine::twine_core::multihash_codetable::Code;
use twine_spec_rng::{PayloadBuilder, RngStrandDetails};

// create a new twine builder
let signer = RingSigner::generate_rs256(2048).unwrap();
let builder = TwineBuilder::new(signer);
// build the strand, specifying the subspec, hasher, and details
let strand = builder.build_strand()
 .subspec(subspec_string())
 .hasher(Code::Sha3_256)
 // specify the period for the strand
 .details(RngStrandDetails { period: TimeDelta::seconds(60) })
 .done()
 .unwrap();

// create a payload builder with the initial randomness
// here we use 32 bytes of 1s for the next randomness
let pb = PayloadBuilder::new([0u8; 32].to_vec(), [1u8; 32].to_vec());

// build the first tixel
let first = builder.build_first(strand)
 .build_payload_then_done(pb.builder())
 .unwrap();

// advance the payload with new randomness
let pb = pb.advance([2u8; 32].to_vec());
// build the next tixel
let second = builder.build_next(&first)
  .build_payload_then_done(pb.builder())
  .unwrap();

// ... continue
```