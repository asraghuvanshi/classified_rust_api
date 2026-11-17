use axum::{
    routing::{get, post, put},
    Router,
};

use super::handlers::{
    change_password, edit_profile, forgot_password, get_profile, login, not_found_handler,
    refresh_token, register, resend_otp, reset_password, upload_image, verify_otp,
};
use crate::state::AppState;

 
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/verify-otp", post(verify_otp))
        .route("/resend-otp", post(resend_otp))
        .route("/login", post(login))
        .route("/refresh-token", post(refresh_token))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        .route("/change-password", post(change_password))
        .route("/profile", get(get_profile))
        .route("/edit-profile", put(edit_profile))
        .route("/upload", post(upload_image))
        .fallback(not_found_handler)
}