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
    // Stage B1.4: prefer `_FILE` indirection (Docker secrets mount
    // `/run/secrets/<name>`) over the plain env var.
    if let Ok(path) = std::env::var("DPSIM_JWT_SECRET_FILE") {
        if !path.is_empty() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_owned());
                }
            }
        }
    }
    std::env::var("DPSIM_JWT_SECRET").ok().filter(|s| !s.is_empty())
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
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .ok()
    .map(|d| d.claims)?;
    // Revocation check — keyed on the JWT signature suffix (session 28).
    // crate::db returns false when redis is unreachable, so local tests
    // without a live redis still pass.
    if let Some(sig) = token_sig_suffix(token) {
        if crate::db::is_token_sig_revoked(sig) {
            return None;
        }
    }
    Some(claims)
}

/// Return the base64url-encoded signature suffix of a JWT (everything after
/// the last `.`). Used as the revocation-list key — fixed size (~43 chars)
/// and unique per token without storing any secret-adjacent material.
pub fn token_sig_suffix(token: &str) -> Option<&str> {
    let dot = token.rfind('.')?;
    let tail = &token[dot + 1..];
    if tail.is_empty() { None } else { Some(tail) }
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

// OpenAPI: advertise the bearer-token scheme so swagger's "Authorize" button
// works and every endpoint guarded by these types shows a lock icon. Reuse a
// single named scheme ("BearerAuth") across MaybeAuthedUser and AuthedUser —
// OpenAPI 3 dedupes by name so the schema emits one definition.
fn bearer_security() -> (String, okapi::openapi3::SecurityScheme, okapi::openapi3::SecurityRequirement) {
    let scheme = okapi::openapi3::SecurityScheme {
        description: Some(
            "JWT returned by POST /auth/login. Supply as `Authorization: Bearer <token>`."
                .into(),
        ),
        data: okapi::openapi3::SecuritySchemeData::Http {
            scheme: "bearer".into(),
            bearer_format: Some("JWT".into()),
        },
        extensions: Default::default(),
    };
    let mut req = okapi::openapi3::SecurityRequirement::new();
    req.insert("BearerAuth".to_owned(), Vec::new());
    ("BearerAuth".to_owned(), scheme, req)
}

impl<'r> OpenApiFromRequest<'r> for MaybeAuthedUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let (name, scheme, req) = bearer_security();
        Ok(RequestHeaderInput::Security(name, scheme, req))
    }
}

impl<'r> OpenApiFromRequest<'r> for AuthedUser {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let (name, scheme, req) = bearer_security();
        Ok(RequestHeaderInput::Security(name, scheme, req))
    }
}

/// Request guard that carries the raw Authorization bearer token string
/// so handlers that need to revoke it (or otherwise inspect it beyond the
/// decoded claims) can get at it without re-parsing headers.
pub struct BearerToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
    type Error = ();
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let header = match req.headers().get_one("Authorization") {
            Some(h) => h,
            None => return Outcome::Error((Status::Unauthorized, ())),
        };
        let token = header.strip_prefix("Bearer ").unwrap_or(header).to_owned();
        if token.is_empty() {
            return Outcome::Error((Status::Unauthorized, ()));
        }
        Outcome::Success(BearerToken(token))
    }
}

impl<'r> OpenApiFromRequest<'r> for BearerToken {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        // Same bearer scheme as AuthedUser — already registered there.
        Ok(RequestHeaderInput::None)
    }
}

/// Guard that resolves the true client IP, honoring proxy headers when
/// `DPSIM_TRUST_PROXY_HEADERS=1` is set. Used to key the per-IP rate-limit
/// bucket on /auth/signup + /auth/login.
///
/// Trust model:
///   - Default (env unset or "0"): only `Request::client_ip()` — the TCP
///     peer. Safe behind a direct deployment.
///   - Opt-in (`DPSIM_TRUST_PROXY_HEADERS=1`): prefer the first entry of
///     `X-Forwarded-For` (comma-separated, leftmost = originating
///     client), falling back to `X-Real-IP`, then the TCP peer. Only
///     enable this when the dpsim-api instance sits behind a trusted
///     reverse proxy / ingress that strips client-supplied copies of
///     the header. Otherwise a malicious client could spoof their IP
///     by sending a custom `X-Forwarded-For`.
///
/// Always returns `None` behind the Rocket test client (no peer socket,
/// no proxy headers).
pub struct ClientIp(pub Option<std::net::IpAddr>);

fn trust_proxy_headers() -> bool {
    matches!(
        std::env::var("DPSIM_TRUST_PROXY_HEADERS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

fn parse_ip_hdr(v: &str) -> Option<std::net::IpAddr> {
    // X-Forwarded-For can be a chain: "client, proxy1, proxy2". Take the
    // first entry (the originating client). Trim whitespace and surrounding
    // brackets common in IPv6 logging. Return None if it doesn't parse.
    let head = v.split(',').next()?.trim();
    let stripped = head.trim_start_matches('[').trim_end_matches(']');
    stripped.parse().ok()
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientIp {
    type Error = ();
    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if trust_proxy_headers() {
            if let Some(xff) = req.headers().get_one("X-Forwarded-For") {
                if let Some(ip) = parse_ip_hdr(xff) {
                    return Outcome::Success(ClientIp(Some(ip)));
                }
            }
            if let Some(xri) = req.headers().get_one("X-Real-IP") {
                if let Some(ip) = parse_ip_hdr(xri) {
                    return Outcome::Success(ClientIp(Some(ip)));
                }
            }
        }
        Outcome::Success(ClientIp(req.client_ip()))
    }
}

impl<'r> OpenApiFromRequest<'r> for ClientIp {
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
    let mut guard = USERS.lock().unwrap_or_else(|e| e.into_inner());
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
///
/// Stage B1.5: prefer the Redis Lua-atomic counter when redis is
/// reachable (so multi-replica dpsim-api deployments share a bucket).
/// Falls back to the in-memory limiter on redis failure.
fn rate_limited(key: &str) -> bool {
    if let Some(count) = crate::db::rate_limit_hit(key, RATE_WINDOW_SECS) {
        // count is AFTER increment, so `>` rather than `>=`.
        return count > RATE_MAX_HITS as u64;
    }
    let now = now_secs();
    let cutoff = now.saturating_sub(RATE_WINDOW_SECS);
    let mut guard = AUTH_HITS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let hits = map.entry(key.to_owned()).or_default();
    hits.retain(|t| *t > cutoff);
    let over = hits.len() >= RATE_MAX_HITS;
    hits.push(now);
    over
}

/// Normalize the email so `Foo@Bar.com` and `foo@bar.com` share a rate
/// bucket. Trim whitespace and ASCII-lowercase — email addresses are
/// case-insensitive per RFC 5321 §4.1.2.
fn norm_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Sweep rate-limit entries whose hits have all expired. Called after each
/// insert so the map doesn't grow unbounded across distinct emails.
fn sweep_rate_limits(now: u64) {
    let cutoff = now.saturating_sub(RATE_WINDOW_SECS);
    let mut guard = AUTH_HITS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = guard.as_mut() {
        map.retain(|_, hits| {
            hits.retain(|t| *t > cutoff);
            !hits.is_empty()
        });
    }
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
    /// v1.2.4 — opaque 32-byte hex string. Use it with POST /auth/refresh
    /// to mint a new access token without re-authenticating. Lives 30 days.
    /// Null when the server failed to persist the token to redis (e.g.
    /// redis unreachable) — existing clients ignore the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// v1.2.4 — access-token TTL in seconds. Echoes issue_token's
    /// `ttl_hours * 3600` so clients can schedule refreshes. Nullable
    /// for back-compat with the pre-v1.2.4 TokenResponse shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// Access token lifetime for this build. 24h is deliberately long — clients
/// that implement /auth/refresh can still rotate frequently, and clients
/// that don't keep working for a day. Shorten to 1h once UI refresh
/// adoption is confirmed (tracked in v1.3).
const ACCESS_TTL_HOURS: i64 = 24;
/// Refresh token lifetime. Matches a typical "long session" window; users
/// who don't interact for a month get bounced back through /auth/login.
const REFRESH_TTL_SECS: u64 = 30 * 24 * 3600;

#[derive(Deserialize, JsonSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Mint a fresh 32-byte hex refresh token and persist it in redis under
/// `auth:refresh:<token>` with the refresh TTL. Returns None when redis
/// is unreachable — callers should proceed with just the access token.
fn mint_refresh_token(user_id: &str, email: &str) -> Option<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    if crate::db::write_refresh_token(&token, user_id, email, REFRESH_TTL_SECS) {
        Some(token)
    } else {
        None
    }
}

/// Rate-limit a request on two keys: the normalized email AND the client IP.
/// If either bucket is already over, return 429; otherwise both buckets
/// record this attempt. Email alone is bypassable (attacker rotates the
/// supplied email); IP alone is too coarse behind NAT. Both together give
/// a reasonable lower bound on attacker throughput. ClientIp::None
/// (Rocket test client) skips the IP bucket.
fn rate_limit_signup_or_login(op: &str, email: &str, ip: &ClientIp) -> Result<(), Status> {
    let now = now_secs();
    let email_over = rate_limited(&format!("{}:{}", op, email));
    let ip_over = match ip.0 {
        Some(addr) => rate_limited(&format!("ip:{}", addr)),
        None => false,
    };
    sweep_rate_limits(now);
    if email_over || ip_over {
        return Err(Status::TooManyRequests);
    }
    Ok(())
}

/// Create a user row. Tries PG first; on "pg disabled" falls back to the
/// in-memory HashMap so tests and DATABASE_URL-less dev runs work unchanged.
async fn create_user(email: &str, password_hash: String) -> Result<User, Status> {
    match crate::pg::insert_user(email, &password_hash).await {
        Ok(crate::pg::UserCreateResult::Created { user_id, email, password_hash }) => {
            Ok(User { id: user_id, email, password_hash })
        }
        Ok(crate::pg::UserCreateResult::Conflict) => Err(Status::Conflict),
        Err(sqlx::Error::Configuration(_)) => {
            // pg disabled — in-memory fallback.
            with_users(|map| {
                if map.contains_key(email) {
                    Err(Status::Conflict)
                } else {
                    let id = uuid::Uuid::new_v4().to_string();
                    let u = User {
                        id:            id,
                        email:         email.to_owned(),
                        password_hash,
                    };
                    map.insert(email.to_owned(), u.clone());
                    Ok(u)
                }
            })
        }
        Err(e) => {
            eprintln!("[auth] pg insert_user error: {}", e);
            Err(Status::ServiceUnavailable)
        }
    }
}

/// Look up a user by email. Same PG-first / in-memory-fallback pattern.
async fn find_user(email: &str) -> Option<User> {
    match crate::pg::get_user_by_email(email).await {
        Ok(Some((user_id, em, hash))) => Some(User { id: user_id, email: em, password_hash: hash }),
        Ok(None) => None,
        Err(sqlx::Error::Configuration(_)) => {
            with_users(|map| map.get(email).cloned())
        }
        Err(e) => {
            eprintln!("[auth] pg get_user error: {}", e);
            None
        }
    }
}

#[rocket_okapi::openapi(skip)]
#[post("/auth/signup", format = "json", data = "<creds>")]
pub async fn signup(
    ip: ClientIp,
    creds: Json<Credentials>,
) -> Result<Json<TokenResponse>, Status> {
    let email = norm_email(&creds.email);
    rate_limit_signup_or_login("signup", &email, &ip)?;
    let ip_str = ip.0.map(|a| a.to_string());
    if creds.password.len() < 8 {
        crate::pg::audit(
            "anon", "auth.signup", Some(&email), "failure",
            None, ip_str.as_deref(),
            Some(serde_json::json!({ "reason": "password_too_short" }))
        ).await;
        return Err(Status::BadRequest);
    }
    let hash = hash_password(&creds.password).map_err(|_| Status::InternalServerError)?;
    let user = create_user(&email, hash).await?;
    let token = issue_token(&user.id, &user.email, ACCESS_TTL_HOURS)
        .ok_or(Status::ServiceUnavailable)?;
    let refresh_token = mint_refresh_token(&user.id, &user.email);
    crate::pg::audit(
        &format!("user:{}", user.id), "auth.signup", Some(&user.email),
        "success", None, ip_str.as_deref(), None,
    ).await;
    Ok(Json(TokenResponse {
        token,
        email: user.email,
        refresh_token,
        expires_in: Some((ACCESS_TTL_HOURS * 3600) as u64),
    }))
}

#[rocket_okapi::openapi(skip)]
#[post("/auth/login", format = "json", data = "<creds>")]
pub async fn login(
    ip: ClientIp,
    creds: Json<Credentials>,
) -> Result<Json<TokenResponse>, Status> {
    let email = norm_email(&creds.email);
    rate_limit_signup_or_login("login", &email, &ip)?;
    let ip_str = ip.0.map(|a| a.to_string());
    let user = match find_user(&email).await {
        Some(u) => u,
        None => {
            crate::pg::audit(
                "anon", "auth.login", Some(&email), "failure",
                None, ip_str.as_deref(),
                Some(serde_json::json!({ "reason": "unknown_email" })),
            ).await;
            return Err(Status::Unauthorized);
        }
    };
    if !verify_password(&creds.password, &user.password_hash) {
        crate::pg::audit(
            &format!("user:{}", user.id), "auth.login", Some(&user.email),
            "failure", None, ip_str.as_deref(),
            Some(serde_json::json!({ "reason": "bad_password" })),
        ).await;
        return Err(Status::Unauthorized);
    }
    let token = issue_token(&user.id, &user.email, ACCESS_TTL_HOURS)
        .ok_or(Status::ServiceUnavailable)?;
    let refresh_token = mint_refresh_token(&user.id, &user.email);
    crate::pg::audit(
        &format!("user:{}", user.id), "auth.login", Some(&user.email),
        "success", None, ip_str.as_deref(), None,
    ).await;
    Ok(Json(TokenResponse {
        token,
        email: user.email,
        refresh_token,
        expires_in: Some((ACCESS_TTL_HOURS * 3600) as u64),
    }))
}

#[rocket_okapi::openapi(skip)]
#[get("/auth/me")]
pub async fn me(user: AuthedUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "sub":   user.0.sub,
        "email": user.0.email,
    }))
}

/// Logout: AuthedUser parses + validates the token via verify_token (which
/// now consults the revocation list, so a second call is idempotent). Then
/// we write the token's signature suffix to redis with TTL = remaining JWT
/// lifetime. Subsequent requests with the same token see the revocation
/// entry and get 401 from the AuthedUser guard.
#[rocket_okapi::openapi(skip)]
#[post("/auth/logout", data = "<body>")]
pub async fn logout(
    user: AuthedUser,
    bearer: BearerToken,
    body: Option<Json<RefreshRequest>>,
) -> Json<serde_json::Value> {
    if let Some(sig) = token_sig_suffix(&bearer.0) {
        let now = Utc::now().timestamp();
        let ttl = ((user.0.exp as i64) - now).max(1) as u64;
        crate::db::revoke_token_sig(sig, ttl);
    }
    // v1.2.4 — if the caller also supplies their refresh token, revoke
    // it so it can't be used to mint new access tokens. Optional so
    // pre-v1.2.4 clients that call /auth/logout without a body still work.
    if let Some(Json(rr)) = body {
        crate::db::revoke_refresh_token(&rr.refresh_token);
    }
    crate::pg::audit(
        &format!("user:{}", user.0.sub), "auth.logout", Some(&user.0.email),
        "success", None, None, None,
    ).await;
    Json(serde_json::json!({ "ok": true }))
}

/// Exchange a refresh token for a fresh access token. Rotates the refresh
/// token — the old one is revoked so a stolen refresh can only be used
/// once before the legitimate user's next call invalidates it.
///
/// 401 when the refresh token is unknown / expired / already-used.
/// 503 when redis is unreachable (can't read the store).
#[rocket_okapi::openapi(skip)]
#[post("/auth/refresh", format = "json", data = "<body>")]
pub async fn refresh(
    ip: ClientIp,
    body: Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, Status> {
    // Rate-limit the refresh path on the same per-IP bucket as login so a
    // stolen refresh can't be brute-forced by a flood. Email is unknown
    // until we look up the token, so we only key by IP here.
    if let Some(addr) = ip.0 {
        if rate_limited(&format!("refresh:ip:{}", addr)) {
            return Err(Status::TooManyRequests);
        }
    }

    let (user_id, email) = match crate::db::read_refresh_token(&body.refresh_token) {
        Some(pair) => pair,
        None => return Err(Status::Unauthorized),
    };

    // Rotate: revoke the presented refresh token immediately. Replay of
    // the same refresh_token after this point returns 401.
    crate::db::revoke_refresh_token(&body.refresh_token);

    let token = issue_token(&user_id, &email, ACCESS_TTL_HOURS)
        .ok_or(Status::ServiceUnavailable)?;
    let new_refresh = mint_refresh_token(&user_id, &email);

    let ip_str = ip.0.map(|a| a.to_string());
    crate::pg::audit(
        &format!("user:{}", user_id), "auth.refresh", Some(&email),
        "success", None, ip_str.as_deref(), None,
    ).await;

    Ok(Json(TokenResponse {
        token,
        email,
        refresh_token: new_refresh,
        expires_in: Some((ACCESS_TTL_HOURS * 3600) as u64),
    }))
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![signup, login, me, logout, refresh]
}
