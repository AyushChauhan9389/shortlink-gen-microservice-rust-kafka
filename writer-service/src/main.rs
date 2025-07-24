use std::{env, time::Duration};

use actix_web::{ dev::Payload, post, web, App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder};
use dotenvy::dotenv;
use futures_util::future::{Ready, ok, err};
use jsonwebtoken::{decode, DecodingKey, Validation};
use rand::{distr::Alphabetic, Rng};
use rdkafka::{producer::{FutureProducer, FutureRecord}, ClientConfig};
use shared::{Claims, CreateLinkRequest, Link, LinkCreatedEvent};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

const KAFKA_TOPIC: &str = "link_created";

pub struct AppState {
    db: PgPool,
    producer: FutureProducer,
    jwt_secret: String,
}

struct AuthenticatedUser{
    user_id: Uuid
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let state = req.app_data::<web::Data<AppState>>().unwrap();
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str["Bearer ".len()..];
                    let key = DecodingKey::from_secret(state.jwt_secret.as_ref());
                    if let Ok(token_data) = decode::<Claims>(token, &key, &Validation::default()) {
                        return ok(AuthenticatedUser { user_id: token_data.claims.sub });
                    }
                }
            }
        }
        err(actix_web::error::ErrorUnauthorized("Invalid or missing token"))
    }
}

#[post("/link")]
async fn create_short_link(
    state: web::Data<AppState>,
    user: AuthenticatedUser,
    req: web::Json<CreateLinkRequest>,
) -> impl Responder {
    let id: String = rand::rng().sample_iter(&Alphabetic).take(6).map(char::from).collect();

    let new_link: Link = match sqlx::query_as(
        "INSERT INTO links (id, original_url, user_id) VALUES ($1, $2, $3) RETURNING *"
    )
    .bind(&id)
    .bind(&req.url) 
    .bind(user.user_id)
    .fetch_one(&state.db)
    .await {
        Ok(link) => link,
        Err(e) => return HttpResponse::InternalServerError().body(format!("DB Error: {}", e)),
    };

    let event = LinkCreatedEvent {
        id: new_link.id.clone(),
        original_url: new_link.original_url.clone(),
        created_at: new_link.created_at.to_rfc3339(),
        user_id: new_link.user_id,
    };
    let producer = state.producer.clone();
    tokio::spawn(async move {
        let payload = serde_json::to_string(&event).expect("Failed to serialize");
        let record = FutureRecord::to(KAFKA_TOPIC).key(&event.id).payload(&payload);
        if let Err((e, _)) = producer.send(record, Duration::from_secs(0)).await {
            eprintln!("Error sending to Kafka: {}", e);
        }
    });

    HttpResponse::Ok().json(serde_json::json!({ "short_url": format!("http://localhost:8080/{}", id) }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let pool = PgPoolOptions::new().connect(&database_url).await.expect("Failed to create Pool");

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", "kafka:9092")
        .set("message.timeout.ms", "5000")
        .create()
        .expect("Producer Creation Error");


    let state = web::Data::new(AppState{db: pool, producer, jwt_secret});

    println!("Writer Service running on port 8081");
    HttpServer::new(move || {
        App::new().app_data(state.clone()).service(create_short_link)
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}