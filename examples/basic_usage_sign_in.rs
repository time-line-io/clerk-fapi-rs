use clerk_fapi_rs::clerk::Clerk;
use clerk_fapi_rs::configuration::ClerkFapiConfiguration;

#[tokio::main]
async fn main() {
    // Example only. Use your own publishable key / base URL.
    let config =
        ClerkFapiConfiguration::new("pk_test_...".to_string(), None, None).expect("bad config");

    let clerk = Clerk::new(config);
    clerk.load().await.expect("failed to load");

    println!("Loaded Clerk. Client id: {}", clerk.client().expect("no client").id);
}


