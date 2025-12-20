use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ResponseContent<T> {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<T>,
}

#[derive(Debug)]
pub enum Error<T> {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent<T>),
}

impl <T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", format!("status code {}", e.status)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl <T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl <T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl <T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl <T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    ::url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                },
                serde_json::Value::String(s) => params.push((format!("{}[{}]", prefix, key), s.clone())),
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}

/// Internal use only
/// A content type supported by this client.
#[allow(dead_code)]
enum ContentType {
    Json,
    Text,
    Unsupported(String)
}

impl From<&str> for ContentType {
    fn from(content_type: &str) -> Self {
        if content_type.starts_with("application") && content_type.contains("json") {
            return Self::Json;
        } else if content_type.starts_with("text/plain") {
            return Self::Text;
        } else {
            return Self::Unsupported(content_type.to_string());
        }
    }
}

pub mod api_keys_api;
#[allow(non_snake_case)]
pub mod active_sessions_api;
pub mod backup_codes_api;
pub mod billing_api;
pub mod client_api;
#[allow(non_snake_case)]
pub mod default_api;
pub mod dev_browser_api;
pub mod domains_api;
#[allow(non_snake_case)]
pub mod email_addresses_api;
pub mod environment_api;
pub mod external_accounts_api;
pub mod health_api;
pub mod invitations_api;
pub mod members_api;
pub mod membership_requests_api;
pub mod o_auth2_callbacks_api;
#[allow(non_snake_case)]
pub mod o_auth2_identity_provider_api;
pub mod organization_api;
pub mod organizations_memberships_api;
#[allow(non_snake_case)]
pub mod passkeys_api;
#[allow(non_snake_case)]
pub mod phone_numbers_api;
pub mod redirect_api;
pub mod roles_api;
pub mod saml_api;
pub mod sessions_api;
pub mod sign_ins_api;
pub mod sign_ups_api;
pub mod totp_api;
#[allow(non_snake_case)]
pub mod user_api;
pub mod waitlist_api;
#[allow(non_snake_case)]
pub mod web3_wallets_api;
pub mod well_known_api;

// Re-export all API functions and typed error enums so that existing code using
// `use crate::apis::*;` continues to compile after regenerations.
pub use active_sessions_api::*;
pub use api_keys_api::*;
pub use backup_codes_api::*;
pub use billing_api::*;
pub use client_api::*;
pub use default_api::*;
pub use dev_browser_api::*;
pub use domains_api::*;
pub use email_addresses_api::*;
pub use environment_api::*;
pub use external_accounts_api::*;
pub use health_api::*;
pub use invitations_api::*;
pub use members_api::*;
pub use membership_requests_api::*;
pub use o_auth2_callbacks_api::*;
pub use o_auth2_identity_provider_api::*;
pub use organization_api::*;
pub use organizations_memberships_api::*;
pub use passkeys_api::*;
pub use phone_numbers_api::*;
pub use redirect_api::*;
pub use roles_api::*;
pub use saml_api::*;
pub use sessions_api::*;
pub use sign_ins_api::*;
pub use sign_ups_api::*;
pub use totp_api::*;
pub use user_api::*;
pub use waitlist_api::*;
pub use web3_wallets_api::*;
pub use well_known_api::*;

pub mod configuration;
