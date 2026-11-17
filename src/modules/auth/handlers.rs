use axum::{extract::State, http::StatusCode, Json};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;
use sha1::{Digest, Sha1};


use super::{
    models::{
        ApiError, ApiResponse, AuthData, ChangePasswordRequest, ForgotPasswordRequest,
        LoginRequest, RefreshTokenRequest, RegisterRequest, ResendOtpRequest,
        ResetPasswordRequest, TokenPair, UpdateProfileRequest, UserProfile, VerifyOtpRequest,
    },
    utils::{
        generate_otp, generate_tokens, hash_password, send_otp_email, verify_password,
        verify_refresh_token, AuthUser,
    },
};

use crate::state::AppState;

#[derive(serde::Serialize)]
pub struct UploadResponse {
    pub url: String,
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

pub async fn not_found_handler() -> ApiError {
    ApiError::not_found("Page not found")
}

// POST /upload
#[axum::debug_handler]
pub async fn upload_image(
    mut multipart: axum::extract::Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), ApiError> {
    let cloud_name = std::env::var("CLOUDINARY_CLOUD_NAME")
        .map_err(|_| ApiError::internal("Cloud name not set"))?;
    let api_key = std::env::var("CLOUDINARY_API_KEY")
        .map_err(|_| ApiError::internal("API key not set"))?;
    let api_secret = std::env::var("CLOUDINARY_API_SECRET")
        .map_err(|_| ApiError::internal("API secret not set"))?;

    let timestamp = chrono::Utc::now().timestamp().to_string();

    let mut file_bytes = Vec::new();
    while let Some(field) = multipart.next_field().await.map_err(|_| ApiError::failure("Invalid multipart field"))? {
        if field.name() == Some("file") {
            file_bytes = field.bytes().await.map_err(|_| ApiError::failure("Failed to read file bytes"))?.to_vec();
            break;
        }
    }

    if file_bytes.is_empty() {
        return Err(ApiError::failure("No image file provided in 'file' field"));
    }

    let signature_string = format!("timestamp={}{}", timestamp, api_secret);
    let mut hasher = Sha1::new();
    hasher.update(signature_string.as_bytes());
    let signature = format!("{:x}", hasher.finalize());

    let client = reqwest::Client::new();
    let url = format!("https://api.cloudinary.com/v1_1/{}/image/upload", cloud_name);

    let form = reqwest::multipart::Form::new()
        .text("api_key", api_key)
        .text("timestamp", timestamp)
        .text("signature", signature)
        .part("file", reqwest::multipart::Part::bytes(file_bytes).file_name("upload.jpg"));

    let res = client
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|_| ApiError::internal("Failed to connect to Cloudinary"))?;

    if !res.status().is_success() {
        return Err(ApiError::internal("Cloudinary upload failed"));
    }

    let json_res: serde_json::Value = res
        .json()
        .await
        .map_err(|_| ApiError::internal("Failed to parse Cloudinary response"))?;

    let secure_url = json_res["secure_url"]
        .as_str()
        .ok_or_else(|| ApiError::internal("Secure URL missing from response"))?
        .to_string();

    Ok((
        StatusCode::OK,
        Json(UploadResponse { url: secure_url }),
    ))
}

//  POST /register
#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let password_hash = hash_password(&payload.password)?;
    let (otp_code, otp_expires_at) = generate_otp();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    let existing_user = sqlx::query!(
        "SELECT id, is_verified as \"is_verified!\" FROM users WHERE email = $1",
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

    let html = format!(
        "<p>Welcome to the marketplace! Your verification code is: <strong>{}</strong></p><p>This code expires in 10 minutes.</p>",
        otp_code
    );
    send_otp_email(payload.email.clone(), "Your Marketplace Verification Code", html)
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

//  POST /verify-otp
#[axum::debug_handler]
pub async fn verify_otp(
    State(state): State<AppState>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthData>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let mut user = sqlx::query_as!(
        FullUserRow,
        r#"
        SELECT id, email, password_hash, first_name as "first_name!", last_name as "last_name!", 
               phone_number as "phone_number!", city as "city!", profile_image, 
               is_verified as "is_verified!", otp_code, otp_expires_at 
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
    let (token, refresh_token) = generate_tokens(user.id)?;

    Ok(ApiResponse::success(
        "Email verified successfully",
        AuthData {
            token: Some(token),
            refresh_token: Some(refresh_token),
            is_verified: true,
            user: UserProfile::from(&user),
        },
    ))
}

//  POST /resend-otp
#[axum::debug_handler]
pub async fn resend_otp(
    State(state): State<AppState>,
    Json(payload): Json<ResendOtpRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let user = sqlx::query!(
        "SELECT id, is_verified as \"is_verified!\" FROM users WHERE email = $1",
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

    let html = format!(
        "<p>Your new verification code is: <strong>{}</strong></p><p>This code expires in 10 minutes.</p>",
        otp_code
    );
    send_otp_email(payload.email.clone(), "Your Marketplace Verification Code", html)
        .await
        .map_err(|_| ApiError::failure("Failed to send verification email"))?;

    tx.commit()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "A new verification code has been sent to your email.",
    ))
}

//  POST /login
#[axum::debug_handler]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(StatusCode, Json<ApiResponse<AuthData>>), ApiError> {
    let user = sqlx::query_as!(
        FullUserRow,
        r#"
        SELECT id, email, password_hash, first_name as "first_name!", last_name as "last_name!", 
               phone_number as "phone_number!", city as "city!", profile_image, 
               is_verified as "is_verified!", otp_code, otp_expires_at 
        FROM users WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::failure("Invalid email or password"))?;

    if !verify_password(&payload.password, &user.password_hash)? {
        return Err(ApiError::failure("Invalid email or password"));
    }

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

        let html = format!(
            "<p>Your verification code is: <strong>{}</strong></p><p>This code expires in 10 minutes.</p>",
            otp_code
        );
        send_otp_email(user.email.clone(), "Your Marketplace Verification Code", html)
            .await
            .map_err(|_| ApiError::failure("Account not verified, and failed to send OTP email"))?;

        tx.commit()
            .await
            .map_err(|_| ApiError::internal("Internal server error"))?;

        return Ok(ApiResponse::success(
            "Account not verified. A verification code has been sent to your email.",
            AuthData {
                token: None,
                refresh_token: None,
                is_verified: false,
                user: UserProfile::from(&user),
            },
        ));
    }

    let (token, refresh_token) = generate_tokens(user.id)?;

    Ok(ApiResponse::success(
        "Login successful",
        AuthData {
            token: Some(token),
            refresh_token: Some(refresh_token),
            is_verified: true,
            user: UserProfile::from(&user),
        },
    ))
}

//  POST /refresh-token (Call this when any protected API returns 401)
#[axum::debug_handler]
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<(StatusCode, Json<ApiResponse<TokenPair>>), ApiError> {
    let user_id = verify_refresh_token(&payload.refresh_token)?;

    // Ensure user still exists in DB
    let exists = sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?
        .unwrap_or(false);

    if !exists {
        return Err(ApiError::session_expired("User session no longer valid"));
    }

    let (token, refresh_token) = generate_tokens(user_id)?;

    Ok(ApiResponse::success(
        "Token refreshed successfully",
        TokenPair {
            token,
            refresh_token,
        },
    ))
}

//  POST /forgot-password (Sends OTP to reset password)
#[axum::debug_handler]
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let user = sqlx::query!("SELECT id FROM users WHERE email = $1", payload.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?
        .ok_or_else(|| ApiError::not_found("No account found with this email"))?;

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

    let html = format!(
        "<p>You requested a password reset. Your OTP code is: <strong>{}</strong></p><p>This code expires in 10 minutes.</p>",
        otp_code
    );
    send_otp_email(payload.email.clone(), "Password Reset OTP", html)
        .await
        .map_err(|_| ApiError::failure("Failed to send password reset email"))?;

    tx.commit()
        .await
        .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "Password reset OTP sent to your email.",
    ))
}

//  POST /reset-password (Verifies OTP and sets new password)
#[axum::debug_handler]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let user = sqlx::query!(
        "SELECT id, otp_code, otp_expires_at FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    let stored_otp = user
        .otp_code
        .as_deref()
        .ok_or_else(|| ApiError::failure("No password reset OTP requested"))?;

    let expires_at = user
        .otp_expires_at
        .ok_or_else(|| ApiError::failure("OTP expiration missing"))?;

    if chrono::Utc::now() > expires_at {
        return Err(ApiError::failure("OTP has expired. Please request a new one."));
    }

    if stored_otp != payload.otp_code {
        return Err(ApiError::failure("Invalid OTP code"));
    }

    let new_hash = hash_password(&payload.new_password)?;

    sqlx::query!(
        "UPDATE users SET password_hash = $1, is_verified = TRUE, otp_code = NULL, otp_expires_at = NULL WHERE id = $2",
        new_hash,
        user.id
    )
    .execute(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "Password reset successfully. You can now log in.",
    ))
}

//  POST /change-password (Authenticated - requires old password)
#[axum::debug_handler]
pub async fn change_password(
    AuthUser(user_id): AuthUser,
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<(StatusCode, Json<ApiResponse<()>>), ApiError> {
    payload
        .validate()
        .map_err(|e| ApiError::failure(format!("Validation error: {}", e)))?;

    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    if !verify_password(&payload.old_password, &user.password_hash)? {
        return Err(ApiError::failure("Current password is incorrect"));
    }

    let new_hash = hash_password(&payload.new_password)?;

    sqlx::query!(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        new_hash,
        user_id
    )
    .execute(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?;

    Ok(ApiResponse::<()>::success_message(
        "Password changed successfully",
    ))
}

//  GET /profile (Authenticated - returns current user profile)
#[axum::debug_handler]
pub async fn get_profile(
    AuthUser(user_id): AuthUser,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<ApiResponse<UserProfile>>), ApiError> {
    let user = sqlx::query_as!(
        FullUserRow,
        r#"
        SELECT id, email, password_hash, first_name as "first_name!", last_name as "last_name!", 
               phone_number as "phone_number!", city as "city!", profile_image, 
               is_verified as "is_verified!", otp_code, otp_expires_at 
        FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal("Internal server error"))?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    Ok(ApiResponse::success(
        "Profile fetched successfully",
        UserProfile::from(&user),
    ))
}

//  POST /edit-profile (Authenticated - updates user profile fields)
#[axum::debug_handler]
pub async fn edit_profile(
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
            id, email, password_hash, first_name as "first_name!", last_name as "last_name!", 
            phone_number as "phone_number!", city as "city!", profile_image, 
            is_verified as "is_verified!", otp_code, otp_expires_at
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