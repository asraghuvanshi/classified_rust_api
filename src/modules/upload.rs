use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use sha1::{Digest, Sha1}; // Optional for signed uploads, or use Cloudinary's SDK/REST API

#[derive(Serialize)]
pub struct UploadResponse {
    pub url: String,
}

#[axum::debug_handler]
pub async fn upload_image(
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadResponse>), String> {
    let cloud_name = std::env::var("CLOUDINARY_CLOUD_NAME").map_err(|_| "Cloud name not set")?;
    let api_key = std::env::var("CLOUDINARY_API_KEY").map_err(|_| "API key not set")?;
    let api_secret = std::env::var("CLOUDINARY_API_SECRET").map_err(|_| "API secret not set")?;

    let timestamp = chrono::Utc::now().timestamp().to_string();

    // Read the file bytes from the incoming multipart form data
    let mut file_bytes = Vec::new();
    while let Some(field) = multipart.next_field().await.map_err(|e| e.to_string())? {
        if field.name() == Some("file") {
            file_bytes = field.bytes().await.map_err(|e| e.to_string()?)?.to_vec();
            break;
        }
    }

    if file_bytes.is_empty() {
        return Err("No image file provided in 'file' field".to_string());
    }

    // Generate SHA-1 signature required by Cloudinary for authenticated uploads
    // signature = SHA1(timestamp=TIMESTAMP + API_SECRET)
    let signature_string = format!("timestamp={}{}", timestamp, api_secret);
    let mut hasher = Sha1::new();
    hasher.update(signature_string.as_bytes());
    let signature = format!("{:x}", hasher.finalize());

    // Build multipart request to Cloudinary's upload API
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
        .map_err(|e| format!("Failed to connect to Cloudinary: {}", e))?;

    if !res.status().is_success() {
        let err_text = res.text().await.unwrap_or_default();
        return Err(format!("Cloudinary error: {}", err_text));
    }

    //  JSON response to extract the secure URL
    let json_res: serde_json::Value = res
        .json()
        .await
        .map_err(|_| "Failed to parse Cloudinary response")?;

    let secure_url = json_res["secure_url"]
        .as_str()
        .ok_or_else(|| "Secure URL missing from response")?
        .to_string();

    Ok((
        StatusCode::OK,
        Json(UploadResponse { url: secure_url }),
    ))
}