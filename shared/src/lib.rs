use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

//JWT Struct
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims{
    pub sub: Uuid,
    pub exp: usize,
}

// UserModel
#[derive(Debug, FromRow)]
pub struct User{
    pub id: Uuid,
    pub username: String,
    pub password_hash: String
}   

//AuthRequest
#[derive(Deserialize)]
pub struct AuthRequest{
    pub username: String,
    pub password: String
}

//AuthResponse
#[derive(Deserialize)]
pub struct CreateLinkRequest{
    pub url: String
}

//postgres data for url
#[derive(Serialize, FromRow, Clone)]
pub struct Link{
    pub id: String,
    pub original_url: String,
    pub created_at: DateTime<Local>,
    pub user_id: Uuid
}

//kalfa Payload
#[derive(Serialize)]
pub struct LinkCreatedEvent{
    pub id: String,
    pub original_url: String,
    pub created_at: String,
    pub user_id: Uuid
}