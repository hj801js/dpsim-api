//! Phase 4.1 — self-hosted JWT auth with argon2id password hashing.
//!
//! - `hash_password` / `verify_password`: argon2id wrapper.
//! - `issue_token` / `verify_token`: HS256 JWT with email + exp claims.
//! - `AuthedUser` request guard: extracts bearer from Authorization header.
//!
//! Routes (`/auth/signup`, `/auth/login`, `/auth/me`) live at the bottom so
//! they can be mounted from main.rs. All storage is in-memory for this phase
//! — backed by the `users` table in `ops/pg/schema.sql` once P2.3 wires
//! sqlx through the rest of the API.
//!
//! Enable via `DPSIM_JWT_SECRET=<secret>` env var; the secret is required
//! (panic if missing) to force explicit opt-in — default dev builds remain
//! fully unauthenticated so smoke.sh keeps working.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::Json;
use rocket_okapi::request::{OpenApiFromRequest, RequestHeaderInput};
use rocket_okapi::gen::OpenApiGenerator;
use schemars::JsonSchema;
use std::collections::HashMap;
use std::sync::Mutex;

// -------------------------------------------------------------------------
// Password hashing (argon2id)
// -------------------------------------------------------------------------
pub fn hash_password(plain: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(plain.as_bytes(), &salt)?.to_string();
    Ok(hash)
}

pub fn verify_password(plain: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default().verify_password(plain.as_bytes(), &parsed).is_ok()
}

// -------------------------------------------------------------------------
// JWT
// -------------------------------------------------------------------------
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub:   String,
    pub email: String,
    pub exp:   usize,
}

fn secret() -> Option<String> {
    std::env::var("DPSIM_JWT_SECRET").ok()
}

pub fn issue_token(user_id: &str, email: &str, ttl_hours: i64) -> Option<String> {
    let secret = secret()?;
    let claims = Claims {
        sub:   user_id.to_owned(),
        email: email.to_owned(),
        exp:   (Utc::now() + Duration::hours(ttl_hours)).timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).ok()
}

pub fn verify_token(token: &str) -> Option<Claims> {
    let secret = secret()?;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)
}

// -------------------------------------------------------------------------
// Request guard
// -------------------------------------------------------------------------
pub struct AuthedUser(pub Claims);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthedUser {
    type Error = ();
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let header = match req.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };
        let token = header.strip_prefix("Bearer ").unwrap_or(header);
        match verify_token(token) {
            Some(claims) => Outcome::Success(AuthedUser(claims)),
            None => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

/// Soft auth guard — produces `Some(claims)` when a valid bearer is present
/// and `None` otherwise. Lets handlers decide whether auth is required based
/// on the `DPSIM_AUTH_REQUIRED` env flag without embedding that decision in
/// the type system (so smoke.sh keeps working unmodified when the flag is
/// unset).
pub struct MaybeAuthedUser(pub Option<Claims>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MaybeAuthedUser {
    type Error = ();
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let header = match req.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Success(MaybeAuthedUser(None)),
        };
        let token = header.strip_prefix("Bearer ").unwrap_or(header);
        Outcome::Success(MaybeAuthedUser(verify_token(token)))
    }
}

// rocket_okapi needs these so guard-using handlers stay in the swagger schema.
// We expose nothing — the guard only reads headers, never rejects the request
// on its own, so from okapi's perspective it's transparent.
impl<'r> OpenApiFromRequest<'r> for MaybeAuthedUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

impl<'r> OpenApiFromRequest<'r> for AuthedUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        Ok(RequestHeaderInput::None)
    }
}

/// True when `DPSIM_AUTH_REQUIRED` env is set to "true"/"1". Handlers
/// consult this to turn `MaybeAuthedUser::None` into a 401.
pub fn auth_required() -> bool {
    matches!(
        std::env::var("DPSIM_AUTH_REQUIRED").as_deref(),
        Ok("true") | Ok("1"),
    )
}

// -------------------------------------------------------------------------
// In-memory user store (replace with pg once P2.3 is wired)
// -------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct User {
    id:            String,
    email:         String,
    password_hash: String,
}

static USERS: Mutex<Option<HashMap<String, User>>> = Mutex::new(None);

fn with_users<T>(f: impl FnOnce(&mut HashMap<String, User>) -> T) -> T {
    let mut guard = USERS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

// -------------------------------------------------------------------------
// Rate limiting — per-email sliding window on /auth/login and /auth/signup
// so a misconfigured client or casual bruteforcer can't hammer argon2id.
// In-memory; resets on process restart. Replace with redis INCR + EXPIRE if
// we ever run more than one dpsim-api replica.
// -------------------------------------------------------------------------
const RATE_WINDOW_SECS: u64 = 60;
const RATE_MAX_HITS:  usize = 5;

static AUTH_HITS: Mutex<Option<HashMap<String, Vec<u64>>>> = Mutex::new(None);

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Returns true when `key` has exceeded RATE_MAX_HITS within the rolling
/// RATE_WINDOW_SECS. Records the hit on the way out regardless — so a
/// caller blocked at attempt 6 still extends the window with attempt 7.
fn rate_limited(key: &str) -> bool {
    let now = now_secs();
    let cutoff = now.saturating_sub(RATE_WINDOW_SECS);
    let mut guard = AUTH_HITS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let hits = map.entry(key.to_owned()).or_default();
    hits.retain(|t| *t > cutoff);
    let over = hits.len() >= RATE_MAX_HITS;
    hits.push(now);
    over
}

// -------------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------------
#[derive(Deserialize, JsonSchema)]
pub struct Credentials {
    pub email:    String,
    pub password: String,
}

#[derive(Serialize, JsonSchema)]
pub struct TokenResponse {
    pub token: String,
    pub email: String,
}

#[rocket_okapi::openapi(skip)]
#[post("/auth/signup", format = "json", data = "<creds>")]
pub async fn signup(creds: Json<Credentials>) -> Result<Json<TokenResponse>, Status> {
    if rate_limited(&format!("signup:{}", creds.email)) {
        return Err(Status::TooManyRequests);
    }
    if creds.password.len() < 8 {
        return Err(Status::BadRequest);
    }
    let user_id = uuid_v4();
    let hash = hash_password(&creds.password).map_err(|_| Status::InternalServerError)?;
    with_users(|map| {
        if map.contains_key(&creds.email) {
            Err(Status::Conflict)
        } else {
            map.insert(creds.email.clone(), User {
                id:            user_id.clone(),
                email:         creds.email.clone(),
                password_hash: hash,
            });
            Ok(())
        }
    })?;
    let token = issue_token(&user_id, &creds.email, 24)
        .ok_or(Status::ServiceUnavailable)?;
    Ok(Json(TokenResponse { token, email: creds.email.clone() }))
}

#[rocket_okapi::openapi(skip)]
#[post("/auth/login", format = "json", data = "<creds>")]
pub async fn login(creds: Json<Credentials>) -> Result<Json<TokenResponse>, Status> {
    if rate_limited(&format!("login:{}", creds.email)) {
        return Err(Status::TooManyRequests);
    }
    let user = with_users(|map| map.get(&creds.email).cloned())
        .ok_or(Status::Unauthorized)?;
    if !verify_password(&creds.password, &user.password_hash) {
        return Err(Status::Unauthorized);
    }
    let token = issue_token(&user.id, &user.email, 24)
        .ok_or(Status::ServiceUnavailable)?;
    Ok(Json(TokenResponse { token, email: user.email }))
}

#[rocket_okapi::openapi(skip)]
#[get("/auth/me")]
pub async fn me(user: AuthedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "sub":   user.0.sub,
        "email": user.0.email,
    }))
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![signup, login, me]
}

// Tiny UUID-v4 — avoid adding the uuid crate just for this.
fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}
