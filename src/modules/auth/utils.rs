use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use resend_rs::{types::CreateEmailBaseOptions, Resend};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::models::ApiError;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub token_type: String, // "access" or "refresh"
    pub exp: usize,
}

pub struct AuthUser(pub Uuid);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| ApiError::refresh_token("Missing authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::refresh_token("Invalid authorization format"))?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret().as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| ApiError::refresh_token("Access token expired or invalid"))?;

        if token_data.claims.token_type != "access" {
            return Err(ApiError::refresh_token("Invalid token type"));
        }

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| ApiError::refresh_token("Invalid token subject"))?;

        Ok(AuthUser(user_id))
    }
}

fn jwt_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_jwt_key".to_string())
}

pub fn generate_tokens(user_id: Uuid) -> Result<(String, String), ApiError> {
    let now = chrono::Utc::now();

    // Short-lived Access Token (1 hour)  triggers 401 when expired
    let access_exp = now
        .checked_add_signed(chrono::Duration::hours(1))
        .ok_or_else(|| ApiError::internal("Invalid timestamp"))?
        .timestamp() as usize;

    let access_claims = Claims {
        sub: user_id.to_string(),
        token_type: "access".to_string(),
        exp: access_exp,
    };

    // Long-lived Refresh Token (30 days) triggers 403 when expired
    let refresh_exp = now
        .checked_add_signed(chrono::Duration::days(30))
        .ok_or_else(|| ApiError::internal("Invalid timestamp"))?
        .timestamp() as usize;

    let refresh_claims = Claims {
        sub: user_id.to_string(),
        token_type: "refresh".to_string(),
        exp: refresh_exp,
    };

    let key = EncodingKey::from_secret(jwt_secret().as_bytes());
    let access_token = encode(&Header::default(), &access_claims, &key)
        .map_err(|_| ApiError::internal("Failed to generate access token"))?;
    let refresh_token = encode(&Header::default(), &refresh_claims, &key)
        .map_err(|_| ApiError::internal("Failed to generate refresh token"))?;

    Ok((access_token, refresh_token))
}

pub fn verify_refresh_token(token: &str) -> Result<Uuid, ApiError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| ApiError::session_expired("Refresh token expired or invalid. Please log in again."))?;

    if token_data.claims.token_type != "refresh" {
        return Err(ApiError::session_expired("Invalid refresh token"));
    }

    Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| ApiError::session_expired("Invalid token subject"))
}

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::internal("Internal server error"))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, ApiError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|_| ApiError::internal("Internal server error"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn generate_otp() -> (String, chrono::DateTime<chrono::Utc>) {
    let mut rng = rand::thread_rng();
    let code: String = rng.gen_range(100000..=999999).to_string();
    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
    (code, expires)
}

pub async fn send_otp_email(to: String, subject: &str, html_body: String) -> Result<(), String> {
    let resend_api_key =
        std::env::var("RESEND_API_KEY").map_err(|_| "RESEND_API_KEY not set".to_string())?;
    let from_email =
        std::env::var("FROM_EMAIL").unwrap_or_else(|_| "onboarding@resend.dev".to_string());

    let resend = Resend::new(&resend_api_key);
    let email_options = CreateEmailBaseOptions::new(from_email, [to], subject).with_html(&html_body);

    resend.emails.send(email_options).await.map_err(|e| e.to_string())?;
    Ok(())
}