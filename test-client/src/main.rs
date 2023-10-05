use oauth2::{ClientId, PkceCodeChallenge, CsrfToken, AuthorizationCode, Scope};
use openidconnect::{core::{CoreProviderMetadata, CoreClient, CoreAuthenticationFlow}, IssuerUrl, reqwest::async_http_client, Nonce, TokenResponse, AccessTokenHash};
use serde::{Deserialize};

const SERVER: &str = "https://blackquill.cc/.well-known/harmony-homeserver";

#[derive(Deserialize)]
struct HarmonyHomeserverWellKnown {
    pub issuer: String,
}

#[tokio::main]
async fn main() {
    let res = reqwest::get(SERVER)
        .await
        .unwrap()
        .json::<HarmonyHomeserverWellKnown>()
        .await
        .unwrap();

    let provider_metadata =
        CoreProviderMetadata::discover_async(
            IssuerUrl::new(res.issuer.clone()).unwrap(),
            async_http_client
        )
        .await
        .unwrap();

    let client =
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new("some_random_key".to_string()),
            None
        );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) =
        client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("urn:harmony:*".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

    println!("Browse to: {}", auth_url);

    let token_response =
        client
            .exchange_code(AuthorizationCode::new("todo: read this from input".to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await
            .unwrap();

    let id_token =
        token_response
            .id_token()
            .unwrap();
    let claims = id_token.claims(&client.id_token_verifier(), &nonce).unwrap();

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        use oauth2::TokenResponse;
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token.signing_alg().unwrap()
        ).unwrap();
        if actual_access_token_hash != *expected_access_token_hash {
            panic!("invalid access token");
        }
    }
}
