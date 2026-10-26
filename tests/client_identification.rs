use clerk_fapi_rs::{
    configuration::ClerkFapiConfiguration,
    models::{ClientClient, ClientSignIn},
    Clerk,
};
use mockito::{Matcher, Server};

const TEST_KEY: &str = "pk_test_Y2xlcmsuZXhhbXBsZS5jb20k";
const APP_USER_AGENT: &str = "ExampleApp/1.0.0 (macOS; aarch64)";

#[tokio::test]
async fn native_defaults_preserve_sdk_identity_and_mobile_header() {
    let mut server = Server::new_async().await;
    let sdk_user_agent = format!("clerk-fapi-rs/{}", env!("CARGO_PKG_VERSION"));
    let request = server
        .mock("GET", "/v1/client")
        .match_query(Matcher::UrlEncoded("_is_native".into(), "1".into()))
        .match_header("user-agent", sdk_user_agent.as_str())
        .match_header("x-mobile", "1")
        .match_header("x-no-origin", "1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({"response": null, "client": null}).to_string())
        .create_async()
        .await;
    let config = ClerkFapiConfiguration::new(TEST_KEY.into(), Some(server.url()), None).unwrap();

    Clerk::new(config)
        .get_fapi_client()
        .get_client()
        .await
        .unwrap();

    request.assert_async().await;
}

#[tokio::test]
async fn desktop_ticket_sign_in_uses_app_identity_and_retains_native_authentication() {
    let mut server = Server::new_async().await;
    let client_request = server
        .mock("GET", "/v1/client")
        .match_query(Matcher::UrlEncoded("_is_native".into(), "1".into()))
        .match_header("user-agent", APP_USER_AGENT)
        .match_header("x-mobile", Matcher::Missing)
        .match_header("x-no-origin", "1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_header("Authorization", "test-native-client-token")
        .with_body(serde_json::json!({"response": null, "client": null}).to_string())
        .create_async()
        .await;
    let sign_in_request = server
        .mock("POST", "/v1/client/sign_ins")
        .match_query(Matcher::UrlEncoded("_is_native".into(), "1".into()))
        .match_header("user-agent", APP_USER_AGENT)
        .match_header("x-mobile", Matcher::Missing)
        .match_header("x-no-origin", "1")
        .match_header("Authorization", "test-native-client-token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("strategy".into(), "ticket".into()),
            Matcher::UrlEncoded("ticket".into(), "test-ticket".into()),
        ]))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::json!({
                "response": ClientSignIn {
                    created_session_id: Some("sess_desktop".into()),
                    ..Default::default()
                },
                "client": ClientClient::default(),
            })
            .to_string(),
        )
        .create_async()
        .await;
    let config = ClerkFapiConfiguration::new(TEST_KEY.into(), Some(server.url()), None)
        .unwrap()
        .with_user_agent(APP_USER_AGENT)
        .unwrap()
        .with_is_mobile(false);
    let clerk = Clerk::new(config);
    let fapi = clerk.get_fapi_client();

    fapi.get_client().await.unwrap();
    let sign_in = fapi
        .create_sign_in(
            None,
            Some("ticket"),
            None,
            None,
            Some("test-ticket"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(sign_in.created_session_id.as_deref(), Some("sess_desktop"));
    client_request.assert_async().await;
    sign_in_request.assert_async().await;
}

#[tokio::test]
async fn explicit_mobile_client_can_supply_app_identity() {
    let mut server = Server::new_async().await;
    let request = server
        .mock("GET", "/v1/client")
        .match_query(Matcher::UrlEncoded("_is_native".into(), "1".into()))
        .match_header("user-agent", APP_USER_AGENT)
        .match_header("x-mobile", "1")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({"response": null, "client": null}).to_string())
        .create_async()
        .await;
    let config = ClerkFapiConfiguration::new(TEST_KEY.into(), Some(server.url()), None)
        .unwrap()
        .with_is_mobile(false)
        .with_is_mobile(true)
        .with_user_agent(APP_USER_AGENT)
        .unwrap();

    Clerk::new(config)
        .get_fapi_client()
        .get_client()
        .await
        .unwrap();

    request.assert_async().await;
}

#[tokio::test]
async fn browser_does_not_send_native_markers() {
    let mut server = Server::new_async().await;
    let request = server
        .mock("GET", "/v1/client")
        .match_header("x-mobile", Matcher::Missing)
        .match_header("x-no-origin", Matcher::Missing)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({"response": null, "client": null}).to_string())
        .create_async()
        .await;
    let config = ClerkFapiConfiguration::new_browser(TEST_KEY.into(), Some(server.url()), None)
        .unwrap()
        .with_is_mobile(true);

    Clerk::new(config)
        .get_fapi_client()
        .get_client()
        .await
        .unwrap();

    request.assert_async().await;
}

#[test]
fn invalid_user_agents_are_rejected_before_client_construction() {
    for user_agent in [
        "",
        "   ",
        "ExampleApp/1.0\r\nx-injected: value",
        "ExampleApp/1.0\0",
    ] {
        let config = ClerkFapiConfiguration::new(TEST_KEY.into(), None, None).unwrap();
        assert!(config.with_user_agent(user_agent).is_err());
    }
}
