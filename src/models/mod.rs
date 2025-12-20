pub mod backup_codes;
pub use self::backup_codes::BackupCodes;
pub mod billing_fee;
pub use self::billing_fee::BillingFee;
pub mod billing_money_response;
pub use self::billing_money_response::BillingMoneyResponse;
pub mod billing_payee;
pub use self::billing_payee::BillingPayee;
pub mod billing_payer;
pub use self::billing_payer::BillingPayer;
pub mod billing_payment_attempt;
pub use self::billing_payment_attempt::BillingPaymentAttempt;
pub mod billing_payment_method;
pub use self::billing_payment_method::BillingPaymentMethod;
pub mod billing_payment_method_initialize;
pub use self::billing_payment_method_initialize::BillingPaymentMethodInitialize;
pub mod billing_plan;
pub use self::billing_plan::BillingPlan;
pub mod billing_plan_features_inner;
pub use self::billing_plan_features_inner::BillingPlanFeaturesInner;
pub mod billing_statement;
pub use self::billing_statement::BillingStatement;
pub mod billing_statement_response_group;
pub use self::billing_statement_response_group::BillingStatementResponseGroup;
pub mod billing_statement_totals_response;
pub use self::billing_statement_totals_response::BillingStatementTotalsResponse;
pub mod billing_subscription;
pub use self::billing_subscription::BillingSubscription;
pub mod billing_subscription_credit_response;
pub use self::billing_subscription_credit_response::BillingSubscriptionCreditResponse;
pub mod billing_subscription_item;
pub use self::billing_subscription_item::BillingSubscriptionItem;
pub mod billing_subscription_item_next_payment;
pub use self::billing_subscription_item_next_payment::BillingSubscriptionItemNextPayment;
pub mod billing_subscription_next_payment;
pub use self::billing_subscription_next_payment::BillingSubscriptionNextPayment;
pub mod clerk_error;
pub use self::clerk_error::ClerkError;
pub mod clerk_errors;
pub use self::clerk_errors::ClerkErrors;
pub mod client_account_portal;
pub use self::client_account_portal::ClientAccountPortal;
pub mod client_account_portal_customization;
pub use self::client_account_portal_customization::ClientAccountPortalCustomization;
pub mod client_active_session;
pub use self::client_active_session::ClientActiveSession;
pub mod client_api_keys_settings;
pub use self::client_api_keys_settings::ClientApiKeysSettings;
pub mod client_auth_config;
pub use self::client_auth_config::ClientAuthConfig;
pub mod client_billing_checkout;
pub use self::client_billing_checkout::ClientBillingCheckout;
pub mod client_billing_generic_array;
pub use self::client_billing_generic_array::ClientBillingGenericArray;
pub mod client_billing_generic_array_response;
pub use self::client_billing_generic_array_response::ClientBillingGenericArrayResponse;
pub mod client_billing_generic_object;
pub use self::client_billing_generic_object::ClientBillingGenericObject;
pub mod client_billing_payment_attempt;
pub use self::client_billing_payment_attempt::ClientBillingPaymentAttempt;
pub mod client_billing_payment_attempt_list;
pub use self::client_billing_payment_attempt_list::ClientBillingPaymentAttemptList;
pub mod client_billing_payment_attempt_list_response;
pub use self::client_billing_payment_attempt_list_response::ClientBillingPaymentAttemptListResponse;
pub mod client_billing_payment_method;
pub use self::client_billing_payment_method::ClientBillingPaymentMethod;
pub mod client_billing_payment_method_initialize;
pub use self::client_billing_payment_method_initialize::ClientBillingPaymentMethodInitialize;
pub mod client_billing_payment_method_list;
pub use self::client_billing_payment_method_list::ClientBillingPaymentMethodList;
pub mod client_billing_payment_method_list_response;
pub use self::client_billing_payment_method_list_response::ClientBillingPaymentMethodListResponse;
pub mod client_billing_statement;
pub use self::client_billing_statement::ClientBillingStatement;
pub mod client_billing_statement_list;
pub use self::client_billing_statement_list::ClientBillingStatementList;
pub mod client_billing_statement_list_response;
pub use self::client_billing_statement_list_response::ClientBillingStatementListResponse;
pub mod client_billing_subscription;
pub use self::client_billing_subscription::ClientBillingSubscription;
pub mod client_billing_subscription_item;
pub use self::client_billing_subscription_item::ClientBillingSubscriptionItem;
pub mod client_billing_subscription_item_list;
pub use self::client_billing_subscription_item_list::ClientBillingSubscriptionItemList;
pub mod client_billing_subscription_item_list_response;
pub use self::client_billing_subscription_item_list_response::ClientBillingSubscriptionItemListResponse;
pub mod client_client;
pub use self::client_client::ClientClient;
pub mod client_client_wrapped_backup_codes;
pub use self::client_client_wrapped_backup_codes::ClientClientWrappedBackupCodes;
pub mod client_client_wrapped_client;
pub use self::client_client_wrapped_client::ClientClientWrappedClient;
pub mod client_client_wrapped_deleted_object;
pub use self::client_client_wrapped_deleted_object::ClientClientWrappedDeletedObject;
pub mod client_client_wrapped_email_address;
pub use self::client_client_wrapped_email_address::ClientClientWrappedEmailAddress;
pub mod client_client_wrapped_external_account;
pub use self::client_client_wrapped_external_account::ClientClientWrappedExternalAccount;
pub mod client_client_wrapped_image;
pub use self::client_client_wrapped_image::ClientClientWrappedImage;
pub mod client_client_wrapped_organization;
pub use self::client_client_wrapped_organization::ClientClientWrappedOrganization;
pub mod client_client_wrapped_organization_domain;
pub use self::client_client_wrapped_organization_domain::ClientClientWrappedOrganizationDomain;
pub mod client_client_wrapped_organization_domains;
pub use self::client_client_wrapped_organization_domains::ClientClientWrappedOrganizationDomains;
pub mod client_client_wrapped_organization_domains_response;
pub use self::client_client_wrapped_organization_domains_response::ClientClientWrappedOrganizationDomainsResponse;
pub mod client_client_wrapped_organization_invitation;
pub use self::client_client_wrapped_organization_invitation::ClientClientWrappedOrganizationInvitation;
pub mod client_client_wrapped_organization_invitation_user_context;
pub use self::client_client_wrapped_organization_invitation_user_context::ClientClientWrappedOrganizationInvitationUserContext;
pub mod client_client_wrapped_organization_invitations;
pub use self::client_client_wrapped_organization_invitations::ClientClientWrappedOrganizationInvitations;
pub mod client_client_wrapped_organization_invitations_response;
pub use self::client_client_wrapped_organization_invitations_response::ClientClientWrappedOrganizationInvitationsResponse;
pub mod client_client_wrapped_organization_invitations_response_one_of;
pub use self::client_client_wrapped_organization_invitations_response_one_of::ClientClientWrappedOrganizationInvitationsResponseOneOf;
pub mod client_client_wrapped_organization_invitations_user_context;
pub use self::client_client_wrapped_organization_invitations_user_context::ClientClientWrappedOrganizationInvitationsUserContext;
pub mod client_client_wrapped_organization_invitations_user_context_response;
pub use self::client_client_wrapped_organization_invitations_user_context_response::ClientClientWrappedOrganizationInvitationsUserContextResponse;
pub mod client_client_wrapped_organization_membership;
pub use self::client_client_wrapped_organization_membership::ClientClientWrappedOrganizationMembership;
pub mod client_client_wrapped_organization_membership_request;
pub use self::client_client_wrapped_organization_membership_request::ClientClientWrappedOrganizationMembershipRequest;
pub mod client_client_wrapped_organization_membership_requests;
pub use self::client_client_wrapped_organization_membership_requests::ClientClientWrappedOrganizationMembershipRequests;
pub mod client_client_wrapped_organization_membership_requests_response;
pub use self::client_client_wrapped_organization_membership_requests_response::ClientClientWrappedOrganizationMembershipRequestsResponse;
pub mod client_client_wrapped_organization_memberships;
pub use self::client_client_wrapped_organization_memberships::ClientClientWrappedOrganizationMemberships;
pub mod client_client_wrapped_organization_memberships_response;
pub use self::client_client_wrapped_organization_memberships_response::ClientClientWrappedOrganizationMembershipsResponse;
pub mod client_client_wrapped_organization_memberships_response_one_of;
pub use self::client_client_wrapped_organization_memberships_response_one_of::ClientClientWrappedOrganizationMembershipsResponseOneOf;
pub mod client_client_wrapped_organization_suggestion;
pub use self::client_client_wrapped_organization_suggestion::ClientClientWrappedOrganizationSuggestion;
pub mod client_client_wrapped_organization_suggestions;
pub use self::client_client_wrapped_organization_suggestions::ClientClientWrappedOrganizationSuggestions;
pub mod client_client_wrapped_organization_suggestions_response;
pub use self::client_client_wrapped_organization_suggestions_response::ClientClientWrappedOrganizationSuggestionsResponse;
pub mod client_client_wrapped_passkey;
pub use self::client_client_wrapped_passkey::ClientClientWrappedPasskey;
pub mod client_client_wrapped_phone_number;
pub use self::client_client_wrapped_phone_number::ClientClientWrappedPhoneNumber;
pub mod client_client_wrapped_roles;
pub use self::client_client_wrapped_roles::ClientClientWrappedRoles;
pub mod client_client_wrapped_roles_response;
pub use self::client_client_wrapped_roles_response::ClientClientWrappedRolesResponse;
pub mod client_client_wrapped_session;
pub use self::client_client_wrapped_session::ClientClientWrappedSession;
pub mod client_client_wrapped_session_reverification;
pub use self::client_client_wrapped_session_reverification::ClientClientWrappedSessionReverification;
pub mod client_client_wrapped_sign_in;
pub use self::client_client_wrapped_sign_in::ClientClientWrappedSignIn;
pub mod client_client_wrapped_sign_up;
pub use self::client_client_wrapped_sign_up::ClientClientWrappedSignUp;
pub mod client_client_wrapped_totp;
pub use self::client_client_wrapped_totp::ClientClientWrappedTotp;
pub mod client_client_wrapped_user;
pub use self::client_client_wrapped_user::ClientClientWrappedUser;
pub mod client_client_wrapped_web3_wallet;
pub use self::client_client_wrapped_web3_wallet::ClientClientWrappedWeb3Wallet;
pub mod client_commerce_settings;
pub use self::client_commerce_settings::ClientCommerceSettings;
pub mod client_commerce_settings_billing;
pub use self::client_commerce_settings_billing::ClientCommerceSettingsBilling;
pub mod client_commerce_settings_billing_user;
pub use self::client_commerce_settings_billing_user::ClientCommerceSettingsBillingUser;
pub mod client_delete_session;
pub use self::client_delete_session::ClientDeleteSession;
pub mod client_deleted_object;
pub use self::client_deleted_object::ClientDeletedObject;
pub mod client_display_config;
pub use self::client_display_config::ClientDisplayConfig;
pub mod client_email_address;
pub use self::client_email_address::ClientEmailAddress;
pub mod client_email_address_verification;
pub use self::client_email_address_verification::ClientEmailAddressVerification;
pub mod client_environment;
pub use self::client_environment::ClientEnvironment;
pub mod client_fraud_settings;
pub use self::client_fraud_settings::ClientFraudSettings;
pub mod client_organization;
pub use self::client_organization::ClientOrganization;
pub mod client_organization_domain;
pub use self::client_organization_domain::ClientOrganizationDomain;
pub mod client_organization_domain_verification;
pub use self::client_organization_domain_verification::ClientOrganizationDomainVerification;
pub mod client_organization_invitation;
pub use self::client_organization_invitation::ClientOrganizationInvitation;
pub mod client_organization_invitation_user_context;
pub use self::client_organization_invitation_user_context::ClientOrganizationInvitationUserContext;
pub mod client_organization_membership;
pub use self::client_organization_membership::ClientOrganizationMembership;
pub mod client_organization_membership_request;
pub use self::client_organization_membership_request::ClientOrganizationMembershipRequest;
pub mod client_organization_settings;
pub use self::client_organization_settings::ClientOrganizationSettings;
pub mod client_organization_suggestion;
pub use self::client_organization_suggestion::ClientOrganizationSuggestion;
pub mod client_passkey;
pub use self::client_passkey::ClientPasskey;
pub mod client_permission;
pub use self::client_permission::ClientPermission;
pub mod client_phone_number;
pub use self::client_phone_number::ClientPhoneNumber;
pub mod client_phone_number_verification;
pub use self::client_phone_number_verification::ClientPhoneNumberVerification;
pub mod client_protect_config;
pub use self::client_protect_config::ClientProtectConfig;
pub mod client_protect_config_loader;
pub use self::client_protect_config_loader::ClientProtectConfigLoader;
pub mod client_public_organization_data;
pub use self::client_public_organization_data::ClientPublicOrganizationData;
pub mod client_public_user_data;
pub use self::client_public_user_data::ClientPublicUserData;
pub mod client_role;
pub use self::client_role::ClientRole;
pub mod client_saml_account;
pub use self::client_saml_account::ClientSamlAccount;
pub mod client_saml_account_verification;
pub use self::client_saml_account_verification::ClientSamlAccountVerification;
pub mod client_session;
pub use self::client_session::ClientSession;
pub mod client_session_activity;
pub use self::client_session_activity::ClientSessionActivity;
pub mod client_session_base;
pub use self::client_session_base::ClientSessionBase;
pub mod client_session_reverification;
pub use self::client_session_reverification::ClientSessionReverification;
pub mod client_session_reverification_first_factor_verification;
pub use self::client_session_reverification_first_factor_verification::ClientSessionReverificationFirstFactorVerification;
pub mod client_session_reverification_second_factor_verification;
pub use self::client_session_reverification_second_factor_verification::ClientSessionReverificationSecondFactorVerification;
pub mod client_session_task;
pub use self::client_session_task::ClientSessionTask;
pub mod client_sign_in;
pub use self::client_sign_in::ClientSignIn;
pub mod client_sign_in_first_factor_verification;
pub use self::client_sign_in_first_factor_verification::ClientSignInFirstFactorVerification;
pub mod client_sign_in_second_factor_verification;
pub use self::client_sign_in_second_factor_verification::ClientSignInSecondFactorVerification;
pub mod client_sign_in_user_data;
pub use self::client_sign_in_user_data::ClientSignInUserData;
pub mod client_sign_up;
pub use self::client_sign_up::ClientSignUp;
pub mod client_sign_up_verifications;
pub use self::client_sign_up_verifications::ClientSignUpVerifications;
pub mod client_sign_up_verifications_external_account;
pub use self::client_sign_up_verifications_external_account::ClientSignUpVerificationsExternalAccount;
pub mod client_user;
pub use self::client_user::ClientUser;
pub mod client_user_settings;
pub use self::client_user_settings::ClientUserSettings;
pub mod client_waitlist_entry;
pub use self::client_waitlist_entry::ClientWaitlistEntry;
pub mod client_web3_wallet;
pub use self::client_web3_wallet::ClientWeb3Wallet;
pub mod client_web3_wallet_verification;
pub use self::client_web3_wallet_verification::ClientWeb3WalletVerification;
pub mod create_api_key_201_response;
pub use self::create_api_key_201_response::CreateApiKey201Response;
pub mod create_api_key_request;
pub use self::create_api_key_request::CreateApiKeyRequest;
pub mod create_organization_payment_method_request;
pub use self::create_organization_payment_method_request::CreateOrganizationPaymentMethodRequest;
pub mod create_session_token_200_response;
pub use self::create_session_token_200_response::CreateSessionToken200Response;
pub mod external_account_with_verification;
pub use self::external_account_with_verification::ExternalAccountWithVerification;
pub mod external_account_with_verification_verification;
pub use self::external_account_with_verification_verification::ExternalAccountWithVerificationVerification;
pub mod fraud_settings_native_settings;
pub use self::fraud_settings_native_settings::FraudSettingsNativeSettings;
pub mod get_api_keys_200_response;
pub use self::get_api_keys_200_response::GetApiKeys200Response;
pub mod get_api_keys_200_response_data_inner;
pub use self::get_api_keys_200_response_data_inner::GetApiKeys200ResponseDataInner;
pub mod get_api_keys_400_response;
pub use self::get_api_keys_400_response::GetApiKeys400Response;
pub mod get_api_keys_400_response_errors_inner;
pub use self::get_api_keys_400_response_errors_inner::GetApiKeys400ResponseErrorsInner;
pub mod get_api_keys_404_response;
pub use self::get_api_keys_404_response::GetApiKeys404Response;
pub mod get_api_keys_404_response_errors_inner;
pub use self::get_api_keys_404_response_errors_inner::GetApiKeys404ResponseErrorsInner;
pub mod get_billing_plan_list_200_response;
pub use self::get_billing_plan_list_200_response::GetBillingPlanList200Response;
pub mod get_health_200_response;
pub use self::get_health_200_response::GetHealth200Response;
pub mod get_health_503_response;
pub use self::get_health_503_response::GetHealth503Response;
pub mod get_o_auth_token_400_response;
pub use self::get_o_auth_token_400_response::GetOAuthToken400Response;
pub mod get_o_auth_token_401_response;
pub use self::get_o_auth_token_401_response::GetOAuthToken401Response;
pub mod get_proxy_health_200_response;
pub use self::get_proxy_health_200_response::GetProxyHealth200Response;
pub mod get_proxy_health_200_response_one_of;
pub use self::get_proxy_health_200_response_one_of::GetProxyHealth200ResponseOneOf;
pub mod image;
pub use self::image::Image;
pub mod jwks;
pub use self::jwks::Jwks;
pub mod jwks_ecdsa_private_key;
pub use self::jwks_ecdsa_private_key::JwksEcdsaPrivateKey;
pub mod jwks_ecdsa_public_key;
pub use self::jwks_ecdsa_public_key::JwksEcdsaPublicKey;
pub mod jwks_ed25519_private_key;
pub use self::jwks_ed25519_private_key::JwksEd25519PrivateKey;
pub mod jwks_ed25519_public_key;
pub use self::jwks_ed25519_public_key::JwksEd25519PublicKey;
pub mod jwks_keys_inner;
pub use self::jwks_keys_inner::JwksKeysInner;
pub mod jwks_rsa_private_key;
pub use self::jwks_rsa_private_key::JwksRsaPrivateKey;
pub mod jwks_rsa_public_key;
pub use self::jwks_rsa_public_key::JwksRsaPublicKey;
pub mod jwks_symmetric_key;
pub use self::jwks_symmetric_key::JwksSymmetricKey;
pub mod o_auth_consent_info;
pub use self::o_auth_consent_info::OAuthConsentInfo;
pub mod o_auth_dynamic_client_registration_error;
pub use self::o_auth_dynamic_client_registration_error::OAuthDynamicClientRegistrationError;
pub mod o_auth_dynamic_client_registration_request;
pub use self::o_auth_dynamic_client_registration_request::OAuthDynamicClientRegistrationRequest;
pub mod o_auth_dynamic_client_registration_response;
pub use self::o_auth_dynamic_client_registration_response::OAuthDynamicClientRegistrationResponse;
pub mod o_auth_scope_with_description;
pub use self::o_auth_scope_with_description::OAuthScopeWithDescription;
pub mod o_auth_token;
pub use self::o_auth_token::OAuthToken;
pub mod o_auth_token_info;
pub use self::o_auth_token_info::OAuthTokenInfo;
pub mod o_auth_user_info;
pub use self::o_auth_user_info::OAuthUserInfo;
pub mod organization_settings_actions_settings;
pub use self::organization_settings_actions_settings::OrganizationSettingsActionsSettings;
pub mod organization_settings_domains_settings;
pub use self::organization_settings_domains_settings::OrganizationSettingsDomainsSettings;
pub mod organization_settings_slug_settings;
pub use self::organization_settings_slug_settings::OrganizationSettingsSlugSettings;
pub mod revoke_api_key_request;
pub use self::revoke_api_key_request::RevokeApiKeyRequest;
pub mod schemas_client_client;
pub use self::schemas_client_client::SchemasClientClient;
pub mod schemas_client_client_wrapped_organization;
pub use self::schemas_client_client_wrapped_organization::SchemasClientClientWrappedOrganization;
pub mod schemas_client_client_wrapped_sign_in;
pub use self::schemas_client_client_wrapped_sign_in::SchemasClientClientWrappedSignIn;
pub mod schemas_client_client_wrapped_user;
pub use self::schemas_client_client_wrapped_user::SchemasClientClientWrappedUser;
pub mod schemas_client_session;
pub use self::schemas_client_session::SchemasClientSession;
pub mod schemas_client_session_base;
pub use self::schemas_client_session_base::SchemasClientSessionBase;
pub mod schemas_client_sign_in;
pub use self::schemas_client_sign_in::SchemasClientSignIn;
pub mod schemas_client_sign_in_second_factor_verification;
pub use self::schemas_client_sign_in_second_factor_verification::SchemasClientSignInSecondFactorVerification;
pub mod schemas_stubs_sign_in_factor;
pub use self::schemas_stubs_sign_in_factor::SchemasStubsSignInFactor;
pub mod set_organization_default_payment_method_request;
pub use self::set_organization_default_payment_method_request::SetOrganizationDefaultPaymentMethodRequest;
pub mod stubs_identification_link;
pub use self::stubs_identification_link::StubsIdentificationLink;
pub mod stubs_saml_connection_saml_account;
pub use self::stubs_saml_connection_saml_account::StubsSamlConnectionSamlAccount;
pub mod stubs_sign_in_factor;
pub use self::stubs_sign_in_factor::StubsSignInFactor;
pub mod stubs_sign_up_verification;
pub use self::stubs_sign_up_verification::StubsSignUpVerification;
pub mod stubs_verification_admin;
pub use self::stubs_verification_admin::StubsVerificationAdmin;
pub mod stubs_verification_backup_code;
pub use self::stubs_verification_backup_code::StubsVerificationBackupCode;
pub mod stubs_verification_from_oauth;
pub use self::stubs_verification_from_oauth::StubsVerificationFromOauth;
pub mod stubs_verification_google_one_tap;
pub use self::stubs_verification_google_one_tap::StubsVerificationGoogleOneTap;
pub mod stubs_verification_invitation;
pub use self::stubs_verification_invitation::StubsVerificationInvitation;
pub mod stubs_verification_link;
pub use self::stubs_verification_link::StubsVerificationLink;
pub mod stubs_verification_oauth;
pub use self::stubs_verification_oauth::StubsVerificationOauth;
pub mod stubs_verification_otp;
pub use self::stubs_verification_otp::StubsVerificationOtp;
pub mod stubs_verification_passkey;
pub use self::stubs_verification_passkey::StubsVerificationPasskey;
pub mod stubs_verification_password;
pub use self::stubs_verification_password::StubsVerificationPassword;
pub mod stubs_verification_saml;
pub use self::stubs_verification_saml::StubsVerificationSaml;
pub mod stubs_verification_saml_error;
pub use self::stubs_verification_saml_error::StubsVerificationSamlError;
pub mod stubs_verification_ticket;
pub use self::stubs_verification_ticket::StubsVerificationTicket;
pub mod stubs_verification_totp;
pub use self::stubs_verification_totp::StubsVerificationTotp;
pub mod stubs_verification_web3_signature;
pub use self::stubs_verification_web3_signature::StubsVerificationWeb3Signature;
pub mod token;
pub use self::token::Token;
pub mod totp;
pub use self::totp::Totp;
pub mod update_api_key_request;
pub use self::update_api_key_request::UpdateApiKeyRequest;
pub mod user_settings_actions_settings;
pub use self::user_settings_actions_settings::UserSettingsActionsSettings;
pub mod user_settings_attack_protection_settings;
pub use self::user_settings_attack_protection_settings::UserSettingsAttackProtectionSettings;
pub mod user_settings_attack_protection_settings_email_link;
pub use self::user_settings_attack_protection_settings_email_link::UserSettingsAttackProtectionSettingsEmailLink;
pub mod user_settings_attack_protection_settings_enumeration_protection;
pub use self::user_settings_attack_protection_settings_enumeration_protection::UserSettingsAttackProtectionSettingsEnumerationProtection;
pub mod user_settings_attack_protection_settings_pii;
pub use self::user_settings_attack_protection_settings_pii::UserSettingsAttackProtectionSettingsPii;
pub mod user_settings_attack_protection_settings_user_lockout;
pub use self::user_settings_attack_protection_settings_user_lockout::UserSettingsAttackProtectionSettingsUserLockout;
pub mod user_settings_attribute;
pub use self::user_settings_attribute::UserSettingsAttribute;
pub mod user_settings_attributes;
pub use self::user_settings_attributes::UserSettingsAttributes;
pub mod user_settings_enterprise_sso;
pub use self::user_settings_enterprise_sso::UserSettingsEnterpriseSso;
pub mod user_settings_passkey_settings;
pub use self::user_settings_passkey_settings::UserSettingsPasskeySettings;
pub mod user_settings_password_settings;
pub use self::user_settings_password_settings::UserSettingsPasswordSettings;
pub mod user_settings_restrictions;
pub use self::user_settings_restrictions::UserSettingsRestrictions;
pub mod user_settings_restrictions_enabled;
pub use self::user_settings_restrictions_enabled::UserSettingsRestrictionsEnabled;
pub mod user_settings_sign_in;
pub use self::user_settings_sign_in::UserSettingsSignIn;
pub mod user_settings_sign_in_second_factor;
pub use self::user_settings_sign_in_second_factor::UserSettingsSignInSecondFactor;
pub mod user_settings_sign_up;
pub use self::user_settings_sign_up::UserSettingsSignUp;
pub mod user_settings_social;
pub use self::user_settings_social::UserSettingsSocial;
pub mod user_settings_socials;
pub use self::user_settings_socials::UserSettingsSocials;
pub mod user_settings_username_settings;
pub use self::user_settings_username_settings::UserSettingsUsernameSettings;
pub mod verification_google_one_tap;
pub use self::verification_google_one_tap::VerificationGoogleOneTap;
pub mod verification_oauth;
pub use self::verification_oauth::VerificationOauth;
pub mod well_known_apple_app_site_association;
pub use self::well_known_apple_app_site_association::WellKnownAppleAppSiteAssociation;
pub mod well_known_apple_app_site_association_webcredentials;
pub use self::well_known_apple_app_site_association_webcredentials::WellKnownAppleAppSiteAssociationWebcredentials;
pub mod well_known_o_auth2_authorization_server_metadata;
pub use self::well_known_o_auth2_authorization_server_metadata::WellKnownOAuth2AuthorizationServerMetadata;
pub mod well_known_open_id_configuration;
pub use self::well_known_open_id_configuration::WellKnownOpenIdConfiguration;

// ---------------------------------------------------------------------------
// Handwritten conversions
// ---------------------------------------------------------------------------

fn try_convert_via_json<T, U>(value: T) -> Option<U>
where
    T: serde::Serialize,
    U: serde::de::DeserializeOwned,
{
    serde_json::to_value(value)
        .ok()
        .and_then(|v| serde_json::from_value::<U>(v).ok())
}

impl From<SchemasClientSession> for ClientSession {
    fn from(value: SchemasClientSession) -> Self {
        // Best effort: the schema types are usually JSON-compatible with the client types.
        if let Some(v) = try_convert_via_json::<SchemasClientSession, ClientSession>(value.clone()) {
            return v;
        }

        // Fallback mapping for known-compatible fields.
        ClientSession {
            id: value.id,
            object: client_session::Object::Session,
            status: match value.status {
                schemas_client_session::Status::Active => client_session::Status::Active,
                schemas_client_session::Status::Revoked => client_session::Status::Revoked,
                schemas_client_session::Status::Ended => client_session::Status::Ended,
                schemas_client_session::Status::Expired => client_session::Status::Expired,
                schemas_client_session::Status::Removed => client_session::Status::Removed,
                schemas_client_session::Status::Abandoned => client_session::Status::Abandoned,
            },
            expire_at: value.expire_at,
            abandon_at: value.abandon_at,
            last_active_at: value.last_active_at,
            last_active_token: value.last_active_token,
            actor: value.actor,
            tasks: None,
            last_active_organization_id: value.last_active_organization_id,
            user: value.user,
            public_user_data: value.public_user_data,
            factor_verification_age: value.factor_verification_age,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<SchemasClientSignIn> for ClientSignIn {
    fn from(value: SchemasClientSignIn) -> Self {
        // Best effort conversion. If it fails, we fall back to a minimal struct.
        if let Some(v) = try_convert_via_json::<SchemasClientSignIn, ClientSignIn>(value.clone()) {
            return v;
        }

        ClientSignIn {
            object: client_sign_in::Object::SignInAttempt,
            id: value.id,
            status: match value.status {
                schemas_client_sign_in::Status::Abandoned => client_sign_in::Status::Abandoned,
                schemas_client_sign_in::Status::NeedsIdentifier => client_sign_in::Status::NeedsIdentifier,
                schemas_client_sign_in::Status::NeedsFirstFactor => client_sign_in::Status::NeedsFirstFactor,
                schemas_client_sign_in::Status::NeedsSecondFactor => client_sign_in::Status::NeedsSecondFactor,
                schemas_client_sign_in::Status::NeedsClientTrust => client_sign_in::Status::NeedsClientTrust,
                schemas_client_sign_in::Status::NeedsNewPassword => client_sign_in::Status::NeedsNewPassword,
                schemas_client_sign_in::Status::Complete => client_sign_in::Status::Complete,
            },
            supported_identifiers: value
                .supported_identifiers
                .into_iter()
                .map(|s| match s {
                    schemas_client_sign_in::SupportedIdentifiers::EmailAddress => {
                        client_sign_in::SupportedIdentifiers::EmailAddress
                    }
                    schemas_client_sign_in::SupportedIdentifiers::PhoneNumber => {
                        client_sign_in::SupportedIdentifiers::PhoneNumber
                    }
                    schemas_client_sign_in::SupportedIdentifiers::Username => {
                        client_sign_in::SupportedIdentifiers::Username
                    }
                    schemas_client_sign_in::SupportedIdentifiers::Web3Wallet => {
                        client_sign_in::SupportedIdentifiers::Web3Wallet
                    }
                    schemas_client_sign_in::SupportedIdentifiers::Passkey => {
                        client_sign_in::SupportedIdentifiers::Passkey
                    }
                })
                .collect(),
            supported_first_factors: None,
            supported_second_factors: None,
            first_factor_verification: value.first_factor_verification,
            second_factor_verification: None,
            identifier: value.identifier,
            user_data: value.user_data,
            created_session_id: value.created_session_id,
            abandon_at: value.abandon_at,
            client_trust_state: value.client_trust_state.map(|inner| {
                inner.map(|s| match s {
                    schemas_client_sign_in::ClientTrustState::Pending => {
                        client_sign_in::ClientTrustState::Pending
                    }
                    schemas_client_sign_in::ClientTrustState::New => client_sign_in::ClientTrustState::New,
                    schemas_client_sign_in::ClientTrustState::Known => {
                        client_sign_in::ClientTrustState::Known
                    }
                })
            }),
        }
    }
}

impl From<SchemasClientClient> for ClientClient {
    fn from(value: SchemasClientClient) -> Self {
        if let Some(v) = try_convert_via_json::<SchemasClientClient, ClientClient>(value.clone()) {
            return v;
        }

        let sessions = value.sessions.into_iter().map(Into::into).collect();
        let sign_in = value.sign_in.map(|s| Box::new((*s).into()));

        ClientClient {
            object: client_client::Object::Client,
            id: value.id,
            sessions,
            sign_in,
            // Note: schema already uses ClientSignUp here.
            sign_up: value.sign_up,
            last_active_session_id: value.last_active_session_id,
            last_authentication_strategy: value.last_authentication_strategy,
            cookie_expires_at: value.cookie_expires_at,
            captcha_bypass: value.captcha_bypass,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}
