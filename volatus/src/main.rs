use std::time::Duration;
use axum::{
    routing::{get, on, MethodFilter, post},
    Router, body::HttpBody, response::IntoResponse, Json, extract::{State, FromRef},
};
use oauth2::{AuthUrl, TokenUrl, Scope};
use openidconnect::{core::{CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType, CoreJwsSigningAlgorithm, CoreClaimName, CoreClaimType, CoreResponseMode, CoreGrantType, CoreClientAuthMethod, CoreJsonWebKeySet}, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, EmptyAdditionalProviderMetadata, UserInfoUrl};
use tower_http::cors::{CorsLayer, Any};
use reqwest::header::{AUTHORIZATION, ACCEPT, ACCEPT_LANGUAGE, CONTENT_LANGUAGE, CONTENT_TYPE};

#[derive(Clone)]
struct Key {
}

#[derive(Clone)]
struct Keys {
    keys: Vec<Key>,
}

async fn json_web_key_set(State(keys): State<Keys>) -> impl IntoResponse {
    let jwks = CoreJsonWebKeySet::new(keys.keys.into_iter().map(|_x| todo!("convert a key into this")).collect());
    Json(jwks)
}
async fn openid_token_endpoint() -> impl IntoResponse {
    todo!("openid_token_endpoint");
}
async fn openid_registration_endpoint() -> impl IntoResponse {
    todo!("openid_registration_endpoint");
}
async fn openid_userinfo_endpoint() -> impl IntoResponse {
    todo!("openid_userinfo_endpoint");
}
async fn openid_configuration() -> impl IntoResponse {
    let signing_algs = || vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256];
    let auth_methods = || vec![
        CoreClientAuthMethod::ClientSecretBasic,
        CoreClientAuthMethod::ClientSecretPost,
        CoreClientAuthMethod::ClientSecretJwt,
        CoreClientAuthMethod::PrivateKeyJwt,
        CoreClientAuthMethod::None,
    ];
    let provider_metadata =
        CoreProviderMetadata::new(
            IssuerUrl::new("https://auth.harmony.toki.club".to_string()).unwrap(),
            AuthUrl::new("https://auth.harmony.toki.club/authorize".to_string()).unwrap(),
            JsonWebKeySetUrl::new("https://auth.harmony.toki.club/json_web_key_set".to_string()).unwrap(),
            vec![
                ResponseTypes::new(vec![CoreResponseType::Code]),
                ResponseTypes::new(vec![CoreResponseType::IdToken]),
                ResponseTypes::new(vec![CoreResponseType::Code, CoreResponseType::IdToken]),
            ],
            vec![CoreSubjectIdentifierType::Public],
            signing_algs(),
            EmptyAdditionalProviderMetadata {}
        )
        .set_token_endpoint(Some(TokenUrl::new("https://auth.harmony.toki.club/oauth2/token".to_string()).unwrap()))
        .set_userinfo_endpoint(Some(UserInfoUrl::new("https://auth.harmony.toki.club/oauth2/userinfo".to_string()).unwrap()))
        .set_scopes_supported(Some(vec![
            Scope::new("openid".to_string()),
            Scope::new("email".to_string()),
        ]))
        .set_claims_supported(Some(vec![
            CoreClaimName::new("iss".to_string()),
            CoreClaimName::new("sub".to_string()),
            CoreClaimName::new("aud".to_string()),
            CoreClaimName::new("iat".to_string()),
            CoreClaimName::new("exp".to_string()),
            CoreClaimName::new("nonce".to_string()),
            CoreClaimName::new("auth_time".to_string()),
            CoreClaimName::new("at_hash".to_string()),
            CoreClaimName::new("c_hash".to_string()),
        ]))
        .set_claim_types_supported(Some(vec![
            CoreClaimType::Normal,
        ]))
        .set_response_modes_supported(Some(vec![
            CoreResponseMode::FormPost,
            CoreResponseMode::Query,
            CoreResponseMode::Fragment,
        ]))
        .set_grant_types_supported(Some(vec![
            CoreGrantType::AuthorizationCode,
            CoreGrantType::RefreshToken,
            CoreGrantType::ClientCredentials,
        ]))
        .set_token_endpoint_auth_methods_supported(Some(auth_methods()))
        .set_userinfo_signing_alg_values_supported(Some(signing_algs()))
        .set_claims_parameter_supported(Some(false))
        .set_request_parameter_supported(Some(false))
        .set_request_uri_parameter_supported(Some(false));

    Json(provider_metadata)
}

fn oauth2_router<S, B>() -> Router<S, B>
where
    Keys: FromRef<S>,
    B: HttpBody + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/oauth2/token",
            post(openid_token_endpoint),
        )
        .route(
            "/oauth2/registration",
            post(openid_registration_endpoint),
        )
        .route(
            "/oauth2/userinfo",
            on(
                MethodFilter::POST | MethodFilter::GET,
                openid_userinfo_endpoint,
            ),
        )
        .route(
            "/json_web_key_set",
            get(json_web_key_set),
        )
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers([
                    AUTHORIZATION,
                    ACCEPT,
                    ACCEPT_LANGUAGE,
                    CONTENT_LANGUAGE,
                    CONTENT_TYPE,
                ])
                .max_age(Duration::from_secs(60 * 60)),
        )
}

#[derive(Clone)]
struct AppState {
    keys: Keys,
}

impl FromRef<AppState> for Keys {
    fn from_ref(app_state: &AppState) -> Keys {
        app_state.keys.clone()
    }
}

#[tokio::main]
async fn main() {
    let state = AppState { keys: Keys { keys: vec![] } };
    let oauth2_routes = oauth2_router().with_state(state);

    axum::Server::bind(&"0.0.0.0:5982".parse().unwrap())
        .serve(oauth2_routes.into_make_service())
        .await
        .unwrap();
}
