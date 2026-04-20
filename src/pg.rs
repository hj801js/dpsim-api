//! Phase 2.3 — optional PostgreSQL cold-history mirror.
//!
//! Redis stays the source of truth for hot state (status/progress). PG is a
//! cold mirror so the UI's "Recent simulations" list survives redis restarts
//! and so multi-user workspace queries are possible.
//!
//! Enabled when `DATABASE_URL` is set (e.g. `postgres://hk@localhost/dpsim`).
//! Every code path calls `pool()` which returns `None` when PG is off, so
//! failure to reach PG never breaks the redis path.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::OnceCell;

use crate::routes::{DomainType, Simulation, SimulationSummary, SimulationType, SolverType};

fn stype_str(t: SimulationType) -> &'static str {
    match t {
        SimulationType::Powerflow => "Powerflow",
        SimulationType::Outage    => "Outage",
    }
}

fn domain_str(d: DomainType) -> &'static str {
    match d {
        DomainType::SP  => "SP",
        DomainType::DP  => "DP",
        DomainType::EMT => "EMT",
    }
}

fn solver_str(s: SolverType) -> &'static str {
    match s {
        SolverType::MNA => "MNA",
        SolverType::DAE => "DAE",
        SolverType::NRP => "NRP",
    }
}

static POOL: OnceCell<Option<PgPool>> = OnceCell::const_new();

async fn init_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    match PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
    {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("[pg] init failed ({}): {}", url, e);
            None
        }
    }
}

pub async fn pool() -> Option<PgPool> {
    POOL.get_or_init(init_pool).await.clone()
}

/// Best-effort mirror of a freshly-written simulation. `user_sub` is the
/// JWT `sub` claim (UUID string); None when auth is off. Ignored if PG is off.
pub async fn insert_simulation(
    sim: &Simulation,
    user_sub: Option<&str>,
) -> Result<(), sqlx::Error> {
    let Some(p) = pool().await else { return Ok(()) };
    let st_str  = stype_str(sim.simulation_type);
    let dom_str = domain_str(sim.domain);
    let sol_str = solver_str(sim.solver);
    // sub is a UUID string we generated in auth::signup — parse back to UUID
    // for the pg column. Best effort; None fills the column with NULL.
    let user_uuid = user_sub.and_then(|s| sqlx::types::Uuid::parse_str(s).ok());
    sqlx::query(
        "INSERT INTO simulations (simulation_id, results_file, model_id, load_profile_id,
             simulation_type, domain, solver, timestep_ms, finaltime_ms, status, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10)
         ON CONFLICT (simulation_id) DO NOTHING",
    )
    .bind(sim.simulation_id as i64)
    .bind(&sim.results_id)
    .bind(&sim.model_id)
    .bind(&sim.load_profile_id)
    .bind(st_str)
    .bind(dom_str)
    .bind(sol_str)
    .bind(sim.timestep as i32)
    .bind(sim.finaltime as i32)
    .bind(user_uuid)
    .execute(&p)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// User store (session 28). In-memory HashMap in auth.rs stays as fallback
// for tests and DATABASE_URL-less runs; when PG is on these are the
// authoritative paths.
// ---------------------------------------------------------------------------

/// Result of create_user: Created holds the new row; Conflict means email
/// already exists. Errors bubble from sqlx only for real DB problems.
pub enum UserCreateResult {
    Created { user_id: String, email: String, password_hash: String },
    Conflict,
}

pub async fn insert_user(
    email: &str,
    password_hash: &str,
) -> Result<UserCreateResult, sqlx::Error> {
    let Some(p) = pool().await else {
        // Caller treats None-pool as "pg disabled"; signal with a distinct
        // error. The pg-less path in auth.rs will fall back to the HashMap.
        return Err(sqlx::Error::Configuration("pg disabled".into()));
    };
    // INSERT ... RETURNING ... is the sqlx way; Conflict (unique violation)
    // comes back as Database error we coerce to a Conflict variant.
    let res = sqlx::query_as::<_, (sqlx::types::Uuid, String, String)>(
        "INSERT INTO users (email, password_hash)
         VALUES ($1, $2)
         RETURNING user_id, email::text, password_hash",
    )
    .bind(email)
    .bind(password_hash)
    .fetch_one(&p)
    .await;
    match res {
        Ok((uuid, em, hash)) => Ok(UserCreateResult::Created {
            user_id: uuid.to_string(),
            email: em,
            password_hash: hash,
        }),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Ok(UserCreateResult::Conflict)
        }
        Err(e) => Err(e),
    }
}

pub async fn get_user_by_email(
    email: &str,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    let Some(p) = pool().await else {
        return Err(sqlx::Error::Configuration("pg disabled".into()));
    };
    let row = sqlx::query_as::<_, (sqlx::types::Uuid, String, String)>(
        "SELECT user_id, email::text, password_hash FROM users WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&p)
    .await?;
    Ok(row.map(|(uuid, em, hash)| (uuid.to_string(), em, hash)))
}

/// Return the N most recent simulations from PG, optionally scoped to a user.
/// None when PG disabled.
pub async fn list_recent(
    limit: i64,
    user_sub: Option<&str>,
) -> Option<Vec<SimulationSummary>> {
    let p = pool().await?;
    let rows: Vec<(i64, String, String)> = match user_sub
        .and_then(|s| sqlx::types::Uuid::parse_str(s).ok())
    {
        Some(uid) => sqlx::query_as(
            "SELECT simulation_id, model_id, simulation_type
               FROM simulations
              WHERE user_id = $2
              ORDER BY created_at DESC
              LIMIT $1",
        )
        .bind(limit)
        .bind(uid)
        .fetch_all(&p)
        .await
        .ok()?,
        None => sqlx::query_as(
            "SELECT simulation_id, model_id, simulation_type
               FROM simulations
              WHERE user_id IS NULL
              ORDER BY created_at DESC
              LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&p)
        .await
        .ok()?,
    };
    Some(
        rows.into_iter()
            .map(|(sid, mid, stype)| SimulationSummary {
                simulation_id: sid as u64,
                model_id:      mid,
                // Loose conversion back — PG stores the serde enum as text.
                simulation_type: match stype.as_str() {
                    "Outage" => crate::routes::SimulationType::Outage,
                    _        => crate::routes::SimulationType::Powerflow,
                },
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Audit log (Stage B1.3). Best-effort insert so audit failures never break
// the primary request. Retention is handled by ops/audit_retention.sh.
// ---------------------------------------------------------------------------

pub async fn audit(
    actor: &str,
    event: &str,
    target: Option<&str>,
    outcome: &str,
    trace_id: Option<&str>,
    ip: Option<&str>,
    details: Option<serde_json::Value>,
) {
    let Some(p) = pool().await else { return };
    let res = sqlx::query(
        "INSERT INTO audit_log (actor, event, target, outcome, trace_id, ip, details)
         VALUES ($1, $2, $3, $4, $5, $6::INET, $7)",
    )
    .bind(actor)
    .bind(event)
    .bind(target)
    .bind(outcome)
    .bind(trace_id)
    .bind(ip)
    .bind(details)
    .execute(&p)
    .await;
    if let Err(e) = res {
        // Never propagate — audit is advisory. Log to stderr so Loki
        // picks it up and an oncall alert can fire if audit stops flowing.
        eprintln!("[audit] insert failed event={} actor={}: {}", event, actor, e);
    }
}
