use axum::Router;
use crate::state::AppState;

pub mod auth;

pub fn api_router() -> Router<AppState> {
    Router::new()
        .nest("/auth", auth::routes::router())
        .fallback(auth::handlers::not_found_handler)
}