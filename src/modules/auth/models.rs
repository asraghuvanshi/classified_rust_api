use serde::{Deserialize, Serialize};
use validator::Validate;


#[derive(Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    
    #[validate(length(min = 6, message = "Password must be at least 6 characters long"))]
    pub password: String,
    
    #[validate(length(min = 2, message = "First name is required"))]
    pub first_name: String,
    
    #[validate(length(min = 2, message = "Last name is required"))]
    pub last_name: String,
    
    pub phone_number: Option<String>,
    pub city: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}