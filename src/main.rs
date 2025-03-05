use twine::prelude::Resolver;
use twine::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // first arg: url to api
  // second arg: twine query to rng tixel
  let args: Vec<String> = std::env::args().collect();
  if args.len() != 3 {
    eprintln!("Usage: {} <url> <query>", args[0]);
    std::process::exit(1);
  }

  let url = &args[1];
  let query = &args[2];

  let client = twine_http_store::reqwest::Client::new();
  let store = twine_http_store::v2::HttpStore::new(client)
    .with_url(url);

  let query: SingleQuery = query.parse()?;
  let result = store.resolve(query).await?;
  let current = result.unpack();
  let prev = store.resolve(current.previous().unwrap()).await?;

  let rand = twine_spec_rng::extract_randomness(&current, &prev)?;

  // print as hex string
  println!("Successfully extracted randomness:");
  println!("{}", hex::encode(rand));

  Ok(())
}