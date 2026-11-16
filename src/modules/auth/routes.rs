use axum::{
    extract::{FromRequestParts, State},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    routing::{post, put},
    Json, Router,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::Rng;
use resend_rs::{types::CreateEmailBaseOptions, Resend};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

use super::models::{
    ApiError, ApiResponse, AuthData, LoginRequest, RegisterRequest, ResendOtpRequest,
    UpdateProfileRequest, UserProfile, VerifyOtpRequest,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/verify-otp", post(verify_otp))
        .route("/resend-otp", post(resend_otp))
        .route("/login", post(login))
        .route("/edit-profile", put(edit_profile))
        .fallback(not_found_handler)
}

async fn not_found_handler() -> ApiError {
    ApiError::not_found("Page not found")
}

#[derive(FromRow)]
struct FullUserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    first_name: String,
    last_name: String,
    phone_number: String,
    city: String,
    profile_image: Option<String>,
    is_verified: bool,
    otp_code: Option<String>,
    otp_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<&FullUserRow> for UserProfile {
    fn from(row: &FullUserRow) -> Self {
        Self {
            id: row.id,
            email: row.email.clone(),
            first_name: row.first_name.clone(),
            last_name: row.last_name.clone(),
            phone_number: row.phone_number.clone(),
            city: row.city.clone(),
            profile_image: row.profile_image.clone(),
            is_verified: row.is_verified,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Extractor to authenticate Bearer JWT tokens
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
            &DecodingKey::from_secret("super_secret_jwt_key".as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| ApiError::refresh_token("Token expired or invalid"))?;

        let user_id = Uuid::parse_str(&token_data.claims.sub)
            .map_err(|_| ApiError::refresh_token("Invalid token subject"))?;

        Ok(AuthUser(user_id))
    }
}

fn generate_jwt(user_id: Uuid) -> Result<String, ApiError> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .ok_or_else(|| ApiError::internal("Invalid timestamp"))?
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("super_secret_jwt_key".as_bytes()),
    )
    .map_err(|_| ApiError::internal("Failed to generate token"))
}

fn generate_otp() -> (String, chrono::DateTime<chrono::Utc>) {
    let mut rng = rand::thread_rng();
    let code: String = rng.gen_range(100000..=999999).to_string();
    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
    (code, expires)
}

async fn send_verification_email(to: String, otp_code: String) -> Result<(), String> {
    let resend_api_key =
        std::env::var("RESEND_API_KEY").map_err(|_| "RESEND_API_KEY not set".to_string())?;
    let from_email =
        std::env::var("FROM_EMAIL").unwrap_or_else(|_| "onboarding@resend.dev".to_string());

    let resend = Resend::new(&resend_api_key);
    let email_options = CreateEmailBaseOptions::new(
        from_email,
        [to],
        "Your Marketplace Verification Code",
    )
    .with_html(&format!(
        "<p>Welcome to the marketplace! Your verification code is: <strong>{}</strong></p><p>This code expires in 10 minutes.</p>",
        otp_code
    ));

    resend.emails.send(email_options).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[axum::debug_handler]
async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| ApiError::internal("Internal server error"))?
        .to_string();

    let (otp_code, otp_expires_at) = generate_otp();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    let existing_user = sqlx::query!(
        "SELECT id, is_verified FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?;

    match existing_user {
        Some(user) if user.is_verified => {
            return Err(ApiError::failure("Email is already registered"));
        }
        Some(user) => {
            sqlx::query!(
                r#"
                UPDATE users 
                SET password_hash = $1, first_name = $2, last_name = $3, phone_number = $4, city = $5, otp_code = $6, otp_expires_at = $7
                WHERE id = $8
                "#,
                password_hash,
                payload.first_name,
                payload.last_name,
                payload.phone_number,
                payload.city,
                otp_code,
                otp_expires_at,
                user.id
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("Internal server error"))?;
        }
        None => {
            let user_id = Uuid::new_v4();
            sqlx::query!(
                r#"
                INSERT INTO users (id, email, password_hash, first_name, last_name, phone_number, city, profile_image, is_verified, otp_code, otp_expires_at) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, FALSE, $8, $9)
                "#,
                user_id,
                payload.email,
                password_hash,
                payload.first_name,
                payload.last_name,
                payload.phone_number,
                payload.city,
                otp_code,
                otp_expires_at
            )
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::internal("Internal server error"))?;
        }
    }

    send_verification_email(payload.email.clone(), otp_code)
        .await
        .map_err(|e| {
            eprintln!("Failed to send email: {}", e);
            ApiError::failure("Failed to send verification email. Please check your email address.")
        })?;

    tx.commit()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "Registration successful. Please verify the OTP sent to your email.",
    ))
}

#[axum::debug_handler]
async fn verify_otp(
    State(state): State<AppState>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthData>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

  let mut user = sqlx::query_as!(
        FullUserRow,
        r#"
        SELECT 
            id, 
            email, 
            password_hash, 
            first_name as "first_name!", 
            last_name as "last_name!", 
            phone_number as "phone_number!", 
            city as "city!", 
            profile_image, 
            is_verified as "is_verified!", 
            otp_code, 
            otp_expires_at 
        FROM users WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    if user.is_verified {
        return Err(ApiError::failure("Account is already verified"));
    }

    let stored_otp = user
        .otp_code
        .as_deref()
        .ok_or_else(|| ApiError::failure("No OTP pending for this account"))?;

    let expires_at = user
        .otp_expires_at
        .ok_or_else(|| ApiError::failure("OTP expiration missing"))?;

    if chrono::Utc::now() > expires_at {
        return Err(ApiError::failure("OTP has expired. Please request a new one."));
    }

    if stored_otp != payload.otp_code {
        return Err(ApiError::failure("Invalid OTP code"));
    }

    sqlx::query!(
        "UPDATE users SET is_verified = TRUE, otp_code = NULL, otp_expires_at = NULL WHERE id = $1",
        user.id
    )
    .execute(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?;

    user.is_verified = true;
    let token = generate_jwt(user.id)?;

    Ok(ApiResponse::success(
        "Email verified successfully",
        AuthData {
            token: Some(token),
            is_verified: true,
            user: UserProfile::from(&user),
        },
    ))
}

#[axum::debug_handler]
async fn resend_otp(
    State(state): State<AppState>,
    Json(payload): Json<ResendOtpRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let user = sqlx::query!(
        "SELECT id, is_verified FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    if user.is_verified {
        return Err(ApiError::failure("Account is already verified"));
    }

    let (otp_code, otp_expires_at) = generate_otp();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    sqlx::query!(
        "UPDATE users SET otp_code = $1, otp_expires_at = $2 WHERE id = $3",
        otp_code,
        otp_expires_at,
        user.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?;

    send_verification_email(payload.email.clone(), otp_code)
        .await
        .map_err(|e| {
            eprintln!("Failed to send email: {}", e);
            ApiError::failure("Failed to send verification email")
        })?;

    tx.commit()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "A new verification code has been sent to your email.",
    ))
}

#[axum::debug_handler]
async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthData>>), ApiError> {
 let mut user = sqlx::query_as!(
        FullUserRow,
        r#"
        SELECT 
            id, 
            email, 
            password_hash, 
            first_name as "first_name!", 
            last_name as "last_name!", 
            phone_number as "phone_number!", 
            city as "city!", 
            profile_image, 
            is_verified as "is_verified!", 
            otp_code, 
            otp_expires_at 
        FROM users WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::failure("Invalid email or password"))?;

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| ApiError::internal("Internal server error"))?;

    let is_valid = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok();

    if !is_valid {
        return Err(ApiError::failure("Invalid email or password"));
    }

    // If user is not verified, generate & send OTP and return is_verified: false without token
    if !user.is_verified {
        let (otp_code, otp_expires_at) = generate_otp();

        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|_| ApiError::internal("Internal server error"))?;

        sqlx::query!(
            "UPDATE users SET otp_code = $1, otp_expires_at = $2 WHERE id = $3",
            otp_code,
            otp_expires_at,
            user.id
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

        send_verification_email(user.email.clone(), otp_code)
            .await
            .map_err(|e| {
                eprintln!("Failed to send email on login: {}", e);
                ApiError::failure("Account not verified, and failed to send verification email")
            })?;

        tx.commit()
            .await
            .map_err(|_| ApiError::internal("Internal server error"))?;

        return Ok(ApiResponse::success(
            "Account not verified. A verification code has been sent to your email.",
            AuthData {
                token: None,
                is_verified: false,
                user: UserProfile::from(&user),
            },
        ));
    }

    let token = generate_jwt(user.id)?;

    Ok(ApiResponse::success(
        "Login successful",
        AuthData {
            token: Some(token),
            is_verified: true,
            user: UserProfile::from(&user),
        },
    ))
}

#[axum::debug_handler]
async fn edit_profile(
    AuthUser(user_id): AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<(StatusCode, Json<ApiResponse<UserProfile>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

let updated_user = sqlx::query_as!(
        FullUserRow,
        r#"
        UPDATE users
        SET
            first_name = COALESCE($1, first_name),
            last_name = COALESCE($2, last_name),
            phone_number = COALESCE($3, phone_number),
            city = COALESCE($4, city),
            profile_image = COALESCE($5, profile_image)
        WHERE id = $6
        RETURNING 
            id, 
            email, 
            password_hash, 
            first_name as "first_name!", 
            last_name as "last_name!", 
            phone_number as "phone_number!", 
            city as "city!", 
            profile_image, 
            is_verified as "is_verified!", 
            otp_code, 
            otp_expires_at
        "#,
        payload.first_name,
        payload.last_name,
        payload.phone_number,
        payload.city,
        payload.profile_image,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(ApiResponse::success(
        "Profile updated successfully",
        UserProfile::from(&updated_user),
    ))
}