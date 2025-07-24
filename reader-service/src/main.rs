use actix_web::{web, get, App, HttpServer, HttpResponse, Responder, FromRequest, HttpRequest};
use actix_web::dev::Payload;
use futures_util::future::{Ready, ok, err};
use dotenvy::dotenv;
use shared::{Claims, Link};
use std::env;
use sqlx::postgres::{PgPool, PgPoolOptions};
use jsonwebtoken::{decode, Validation, DecodingKey};
use uuid::Uuid;

pub struct AppState {
    db: PgPool,
    jwt_secret: String,
}

struct AuthenticatedUser {
    user_id: Uuid,
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state =  req.app_data::<web::Data<AppState>>().unwrap();

        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str["Bearer ".len()..];
                    let key = DecodingKey::from_secret(state.jwt_secret.as_ref());

                    if let Ok(token_data) = decode::<Claims>(token, &key, &Validation::default()){
                        return ok(AuthenticatedUser { user_id: token_data.claims.sub });
                    } 
                }
            }
        }
        err(actix_web::error::ErrorUnauthorized("Invalid or missing token"))
    }
    
}



#[get("/{id}")]
async fn redirect(state: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    match sqlx::query_as::<_, Link>("SELECT * FROM links WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await {
        Ok(link) => HttpResponse::Found().append_header(("Location", link.original_url)).finish(),
        Err(_) => HttpResponse::NotFound().body("Not Found"),
    }
}

#[get("/links")]
async fn get_user_links(
    state: web::Data<AppState>,
    user: AuthenticatedUser
) -> impl Responder{
    match sqlx::query_as::<_, Link>("SELECT * FROM links WHERE user_id = $1")
    .bind(user.user_id)
    .fetch_all(&state.db)
    .await {
        Ok(links) => HttpResponse::Ok().json(links),
        Err(_) => HttpResponse::NotFound().body("No links found"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let pool = PgPoolOptions::new().connect(&database_url).await.expect("Failed to create pool.");
    let state = web::Data::new(AppState { db: pool, jwt_secret });

    println!("Reader service running on http://localhost:8080");
    HttpServer::new(move || {
        App::new().app_data(state.clone()).service(redirect).service(get_user_links)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
