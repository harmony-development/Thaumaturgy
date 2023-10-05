use axum::{
    routing::get,
    Router,
};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async {

        }));

    axum::Server::bind(&"0.0.0.0:5982".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
