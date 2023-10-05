use std::{io, ops::Range, sync::Arc};

use axum::{Router, routing::get, extract::Query};
use oauth2::{ClientId, PkceCodeChallenge, CsrfToken, AuthorizationCode, Scope, RedirectUrl};
use openidconnect::{core::{CoreProviderMetadata, CoreClient, CoreAuthenticationFlow}, IssuerUrl, reqwest::async_http_client, Nonce, TokenResponse, AccessTokenHash};
use reqwest::Url;
use serde::{Deserialize};
use tokio::{sync::{oneshot, Mutex}, net::TcpListener};
use rand::{thread_rng, Rng};

// const SERVER: &str = "https://blackquill.cc/.well-known/harmony-homeserver";

#[derive(Deserialize)]
struct HarmonyHomeserverWellKnown {
    pub issuer: String,
}

#[derive(Deserialize, Debug)]
struct OAuth2CallbackResponse {
    pub code: String,
    pub state: String,
}

async fn spawn_local_server() -> Result<(Url, oneshot::Receiver<OAuth2CallbackResponse>, oneshot::Sender<()>), ()> {
    const SSO_SERVER_BIND_RANGE: Range<u16> = 20000..30000;
    const SSO_SERVER_BIND_TRIES: u8 = 10;

    let (signal_tx, signal_rx) = oneshot::channel::<()>();
    let (data_tx, data_rx) = oneshot::channel::<OAuth2CallbackResponse>();
    let data_tx_mutex = Arc::new(Mutex::new(Some(data_tx)));

    let mut redirect_url = Url::parse("http://127.0.0.1:0/")
        .expect("Couldn't parse loopback URL");

    let listener = {
        let host = redirect_url.host_str().expect("should have host");
        let mut n = 0;

        loop {
            let port = thread_rng().gen_range(SSO_SERVER_BIND_RANGE);
            match TcpListener::bind((host, port)).await {
                Ok(l) => {
                    redirect_url
                        .set_port(Some(port))
                        .expect("could not set port");
                    break l;
                }
                Err(_) if n < SSO_SERVER_BIND_TRIES => {
                    n += 1;
                }
                Err(_) => {
                    return Err(());
                }
            }
        }
    };

    let server = axum::Server::from_tcp(listener.into_std().unwrap())
        .unwrap()
        .serve(Router::new()
            .route("/", get(move |request: Query<OAuth2CallbackResponse>| {
                let data_tx_mutex = data_tx_mutex.clone();
                async move {
                    if let Some(data_tx) = data_tx_mutex.lock().await.take() {
                        data_tx.send(request.0).expect("The receiver is still alive");
                    }

                    "The authorization step is complete. You can close this page and return to the app."
                }
            })).into_make_service())
        .with_graceful_shutdown(async {
            signal_rx.await.ok();
        });

    tokio::spawn(server);

    Ok((redirect_url, data_rx, signal_tx))
}

#[tokio::main]
async fn main() {
    // let res = reqwest::get(SERVER)
    //     .await
    //     .unwrap()
    //     .json::<HarmonyHomeserverWellKnown>()
    //     .await
    //     .unwrap();
    let (redirect_uri, data_rx, signal_tx) = spawn_local_server().await.unwrap();

    let provider_metadata =
        CoreProviderMetadata::discover_async(
            IssuerUrl::new("https://ldap.toki.club/oauth2/openid/harmony".to_string()).unwrap(),
            async_http_client
        )
        .await
        .unwrap();

    let client =
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new("harmony".to_string()),
            None
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).unwrap());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) =
        client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            // .add_scope(Scope::new("urn:harmony:*".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

    println!("Browse to: {}", auth_url)
;
    let response = data_rx.await.unwrap();
    signal_tx.send(()).expect("Receiver still alive");

    if csrf_token.secret() != &response.state {
        panic!("csrf token secret does not equal state {:?} {:?}", csrf_token.secret(), response.state);
    }

    let token_response =
        client
            .exchange_code(AuthorizationCode::new(response.code))
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
