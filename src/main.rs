use axum::{
    routing::get,
    Router,
};

mod state;
mod db;
mod modules;

use state::AppState;

#[tokio::main]
async fn main() {
    // Initialize database pool and tables via the db module
    let pool = db::init_db().await;
    let state = AppState { db: pool };

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1", modules::api_router())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}