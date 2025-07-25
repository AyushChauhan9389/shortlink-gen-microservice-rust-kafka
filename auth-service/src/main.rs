use actix_web::{middleware, post, web, App, HttpResponse, HttpServer, Responder};
use argon2::password_hash::rand_core::OsRng;
use dotenvy::dotenv;
use sqlx::postgres::{PgPool, PgPoolOptions};
use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Duration, Local};
use uuid::Uuid;

use shared::{AuthRequest, User, Claims};

pub struct AppState{
    db: PgPool,
    jwt_secret: String,
}




#[post("/register")]
async fn register(state: web::Data<AppState>, req: web::Json<AuthRequest>) -> impl Responder {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(req.password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let user_id = Uuid::new_v4();
    let result = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&req.username)
        .bind(&password_hash)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"user_id": user_id, "username": req.username.clone()})),
        Err(e) => {
            log::error!("Error registering user: {}", e);
            HttpResponse::Conflict().body("Username already exists")
        }
    }
}

#[post("/login")]
async fn login(state: web::Data<AppState>, req: web::Json<AuthRequest>) -> impl Responder {
    let user: User = match sqlx::query_as("SELECT * FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_one(&state.db)
        .await {
            Ok(user) => user,
            Err(_) => return HttpResponse::Unauthorized().body("Invalid credentials"),
    };

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().body("Error verifying password"),
    };

    if Argon2::default().verify_password(req.password.as_bytes(), &parsed_hash).is_err() {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }

    let expiration = Local::now().checked_add_signed(Duration::hours(24)).expect("Failed to add 24 hours to current time").timestamp();
    let claims = Claims { sub: user.id, exp: expiration as usize };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_ref()))
        .unwrap_or_else(|_| panic!("Failed to encode token"));

    HttpResponse::Ok().json(serde_json::json!({"token": token}))
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let pool = PgPoolOptions::new().connect(&database_url).await.expect("Failed to connect to Postgres");
    let state = web::Data::new(AppState{db: pool, jwt_secret});

    log::info!("Starting Auth Service on port 8082");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(middleware::Logger::default())
            .service(register)
            .service(login)
    })
        .bind(("0.0.0.0", 8082))?
        .run()
        .await
    
}
