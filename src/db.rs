
extern crate redis;
use redis::{Commands, RedisResult};
use crate::routes::Simulation;

fn get_connection() -> redis::RedisResult<redis::Connection> {
    let url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://redis-master/".into());
    let client = redis::Client::open(url)?;
    client.get_connection()
}

pub fn get_number_of_simulations() -> RedisResult<u64> {
    let mut conn = get_connection()?;
    conn.get("models")
}

#[doc = "Function for requesting a new Simulation id from the Redis DB"]
pub fn get_new_simulation_id() -> RedisResult<u64> {
    let mut conn = get_connection()?;
    conn.incr("models", 1)
}

#[doc = "Function for writing a Simulation into a Redis DB"]
pub fn write_simulation(key: &String, value: &Simulation) -> Result<(), redis::RedisError> {
    let mut conn = get_connection()?;
    match serde_json::to_string(value) {
        Ok(value_str) => conn.set(key, value_str),
        Err(e) => Err((redis::ErrorKind::IoError, "".into(), e.to_string()).into())
    }
}

use redis::RedisError;

// ---------------------------------------------------------------------------
// JWT revocation (session 28). We key the redis entries on the token's
// signature suffix (everything after the last dot in the JWT) so we never
// put the secret-adjacent header/payload in storage and each key is a
// fixed ~43 bytes. TTL matches the token's remaining lifetime.
// ---------------------------------------------------------------------------
#[doc = "Mark a JWT as revoked. `sig` is the base64url-encoded signature (the \
         tail of the JWT after the last dot). `ttl_secs` should be the token's \
         remaining lifetime so the key expires with it."]
pub fn revoke_token_sig(sig: &str, ttl_secs: u64) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("auth:revoked:{}", sig);
    conn.set_ex::<_, _, ()>(key, "1", ttl_secs as usize).is_ok()
}

#[doc = "Returns true when the given signature is in the revocation list. \
         Redis unreachable → false so tests don't need a live redis."]
pub fn is_token_sig_revoked(sig: &str) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("auth:revoked:{}", sig);
    conn.exists(key).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Atomic rate limit (Stage B1.5). INCR + EXPIRE executed as one Lua script
// so concurrent callers can't see an intermediate state where the counter
// exists without a TTL (which would never expire). Returns the count after
// increment, or None when redis is unreachable.
//
// Callers treat None as "redis down → fall back to the in-memory limiter"
// so the request path stays alive through a transient redis outage.
//
// The script returns the new counter value:
//   redis.call('INCR', KEYS[1])
//   if result == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
//   return result
// ---------------------------------------------------------------------------
const RATE_LIMIT_LUA: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"#;

// ---------------------------------------------------------------------------
// Simulation cancel flag (v1.1.3). Worker checks `sim:<id>:canceled` before
// starting work; if present, acknowledges the AMQP message and skips.
// 30-day TTL so redis doesn't grow unbounded with old flags.
// ---------------------------------------------------------------------------
pub fn mark_sim_canceled(sim_id: u64) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("sim:{}:canceled", sim_id);
    conn.set_ex::<_, _, ()>(key, "1", 30 * 24 * 3600).is_ok()
}

pub fn is_sim_canceled(sim_id: u64) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("sim:{}:canceled", sim_id);
    conn.exists(key).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Refresh token store (v1.2.4). Stateless access tokens (JWT, 1h) remain
// but each login also issues a long-lived refresh token (random 32-byte
// hex, 30d) that dpsim-api persists in redis so we can invalidate it at
// logout and prevent reuse after rotation.
//
// Key: `auth:refresh:<token>` → JSON {user_id, email, exp}. TTL matches
// the exp so redis cleans itself up.
// ---------------------------------------------------------------------------
pub fn write_refresh_token(
    token: &str,
    user_id: &str,
    email: &str,
    ttl_secs: u64,
) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("auth:refresh:{}", token);
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) + ttl_secs;
    let v = serde_json::json!({
        "user_id": user_id,
        "email":   email,
        "exp":     exp,
    }).to_string();
    conn.set_ex::<_, _, ()>(key, v, ttl_secs as usize).is_ok()
}

pub fn read_refresh_token(token: &str) -> Option<(String, String)> {
    let mut conn = get_connection().ok()?;
    let key = format!("auth:refresh:{}", token);
    let raw: String = conn.get(&key).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let user_id = v.get("user_id")?.as_str()?.to_string();
    let email   = v.get("email")?.as_str()?.to_string();
    Some((user_id, email))
}

pub fn revoke_refresh_token(token: &str) -> bool {
    let Ok(mut conn) = get_connection() else { return false };
    let key = format!("auth:refresh:{}", token);
    conn.del::<_, u64>(key).map(|n| n > 0).unwrap_or(false)
}

pub fn rate_limit_hit(bucket: &str, window_secs: u64) -> Option<u64> {
    let mut conn = get_connection().ok()?;
    let key = format!("rl:{}", bucket);
    let script = redis::Script::new(RATE_LIMIT_LUA);
    script
        .key(&key)
        .arg(window_secs as usize)
        .invoke::<u64>(&mut conn)
        .ok()
}

#[doc = "Function for reading a Simulation from a Redis DB"]
pub fn read_simulation(key: u64) -> Result<Simulation, RedisError> {
    let mut conn = get_connection()?;
    match conn.get::<u64, Vec<u8>>(key) {
        Ok(value_utf8) => {
            if value_utf8.len() == 0 {
                return Err(RedisError::from((redis::ErrorKind::IoError,
                    "Simulation does not exist in database".into(), key.to_string())))
            }
            match String::from_utf8(value_utf8) {
                Ok(value_string) => match serde_json::from_str(&value_string) {
                    Ok(sim) => Ok(sim),
                    Err(e) => {
                        let error_string = format!("value: {} error: {}", value_string, e.to_string());
                        Err(RedisError::from((redis::ErrorKind::IoError,
                            "Could not convert string to Simulation! ", error_string.into())))
                    }
                }
                Err(e) => return Err((redis::ErrorKind::IoError,
                    "Could not convert utf8 from Redis into string: ".into(), e.to_string()).into())
            }
        }
        Err(e) => return Err((redis::ErrorKind::IoError,
            "Could not fetch item from Redis: ".into(), e.to_string()).into())
    }
}
