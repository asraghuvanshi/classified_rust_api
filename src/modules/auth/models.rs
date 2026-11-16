use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub status_code: u16,
    pub message: String,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(message: impl Into<String>, data: T) -> (StatusCode, Json<Self>) {
        (
            StatusCode::OK,
            Json(Self {
                status_code: 200,
                message: message.into(),
                data: Some(data),
            }),
        )
    }

    pub fn success_message(message: impl Into<String>) -> (StatusCode, Json<ApiResponse<()>>) {
        (
            StatusCode::OK,
            Json(ApiResponse {
                status_code: 200,
                message: message.into(),
                data: None,
            }),
        )
    }
}

pub enum AppErrorCode {
    Failure,        // 0
    RefreshToken,   // 401
    SessionExpired, // 403
    NotFound,       // 404
    InternalError,  // 500
}

pub struct ApiError {
    pub code: AppErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            code: AppErrorCode::Failure,
            message: message.into(),
        }
    }

    pub fn refresh_token(message: impl Into<String>) -> Self {
        Self {
            code: AppErrorCode::RefreshToken,
            message: message.into(),
        }
    }

    pub fn session_expired(message: impl Into<String>) -> Self {
        Self {
            code: AppErrorCode::SessionExpired,
            message: message.into(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: AppErrorCode::NotFound,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: AppErrorCode::InternalError,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (http_status, custom_code) = match self.code {
            AppErrorCode::Failure => (StatusCode::BAD_REQUEST, 0),
            AppErrorCode::RefreshToken => (StatusCode::UNAUTHORIZED, 401),
            AppErrorCode::SessionExpired => (StatusCode::FORBIDDEN, 403),
            AppErrorCode::NotFound => (StatusCode::NOT_FOUND, 404),
            AppErrorCode::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, 500),
        };

        let body = Json(ApiResponse::<()> {
            status_code: custom_code,
            message: self.message,
            data: None,
        });

        (http_status, body).into_response()
    }
}

#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String,
    pub city: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Validate)]
pub struct VerifyOtpRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(equal = 6))]
    pub otp_code: String,
}

#[derive(Deserialize, Validate)]
pub struct ResendOtpRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub city: Option<String>,
    pub profile_image: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub phone_number: String,
    pub city: String,
    pub profile_image: Option<String>,
    pub is_verified: bool,
}

#[derive(Serialize)]
pub struct AuthData {
    pub token: Option<String>,
    pub is_verified: bool,
    pub user: UserProfile,
}