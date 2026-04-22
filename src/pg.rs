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

/// Optional filters for list_recent (v1.2.2).
/// All fields nil → behave as the v1.1.1 list (no filtering beyond user scope).
#[derive(Default, Debug, Clone)]
pub struct ListFilters {
    pub status:   Option<String>,   // queued | running | done | failed | canceled
    pub domain:   Option<String>,   // SP | DP | EMT
    pub model_id: Option<String>,   // exact match on the opaque model id
}

/// Sort options for list_recent (v1.2.9). Allowlist-validated at the route
/// layer so these strings are safe to interpolate into ORDER BY without
/// parameter binding (PG forbids binding identifiers).
#[derive(Default, Debug, Clone)]
pub struct ListSort {
    pub key:   Option<String>,   // "simulation_id" | "created_at" | "status" | "domain"
    pub order: Option<String>,   // "asc" | "desc"
}

/// Resolve sort key + order to a safe `ORDER BY` fragment, defaulting to
/// `created_at DESC`. Any input outside the allowlist silently degrades
/// to the default so malformed params don't 400 the list endpoint.
pub fn sort_fragment(sort: &ListSort) -> &'static str {
    let key = match sort.key.as_deref() {
        Some("simulation_id") => "simulation_id",
        Some("created_at")    => "created_at",
        Some("status")        => "status",
        Some("domain")        => "domain",
        _                     => "created_at",
    };
    let order = match sort.order.as_deref() {
        Some("asc") | Some("ASC")   => "ASC",
        _                           => "DESC",
    };
    // Static str table — only four keys × two orders, so enumerate to
    // keep the return type `&'static str` (safe for format! interpolation).
    match (key, order) {
        ("simulation_id", "ASC")  => "simulation_id ASC",
        ("simulation_id", "DESC") => "simulation_id DESC",
        ("created_at",    "ASC")  => "created_at ASC",
        ("created_at",    "DESC") => "created_at DESC",
        ("status",        "ASC")  => "status ASC",
        ("status",        "DESC") => "status DESC",
        ("domain",        "ASC")  => "domain ASC",
        ("domain",        "DESC") => "domain DESC",
        _                         => "created_at DESC",
    }
}

/// Return `limit` simulations starting at `offset`, scoped to a user if
/// supplied and filtered per `filters`. Returns (rows, total_count) where
/// `total_count` reflects the filtered set, not the full table, so UIs
/// can render accurate "X of N" even under a filter. None when PG disabled.
pub async fn list_recent(
    limit: i64,
    offset: i64,
    user_sub: Option<&str>,
    filters: &ListFilters,
    sort: &ListSort,
) -> Option<(Vec<SimulationSummary>, i64)> {
    let p = pool().await?;
    let uid_opt = user_sub.and_then(|s| sqlx::types::Uuid::parse_str(s).ok());

    // Build WHERE clause dynamically. Binding indices shift with each
    // appended filter; we track them via a counter to avoid off-by-one.
    // Note: sqlx doesn't have a QueryBuilder we can reuse across query_as
    // and query_scalar cleanly at this version, so we interpolate the
    // `WHERE` fragments (with bound placeholders) into both statements.
    let mut where_parts: Vec<String> = Vec::new();
    let mut idx = 3i32; // $1 = limit, $2 = offset; filters start at $3
    where_parts.push(match uid_opt {
        Some(_) => {
            let p = format!("user_id = ${}", idx); idx += 1; p
        }
        None => "user_id IS NULL".to_string(),
    });
    let filter_status = filters.status.clone().filter(|s| !s.is_empty());
    let filter_domain = filters.domain.clone().filter(|s| !s.is_empty());
    let filter_model  = filters.model_id.clone().filter(|s| !s.is_empty());
    if filter_status.is_some() { where_parts.push(format!("status = ${}", idx)); idx += 1; }
    if filter_domain.is_some() { where_parts.push(format!("domain = ${}", idx)); idx += 1; }
    if filter_model.is_some()  { where_parts.push(format!("model_id = ${}", idx)); idx += 1; }
    let _ = idx; // final value intentionally unused — counter is write-only past this point
    let where_sql = where_parts.join(" AND ");

    // v1.2.6 — pull status + domain so SimulationSummary can carry them,
    // eliminating the UI's per-row /api/sim-status fetch. `engine` column
    // doesn't exist in the schema yet (planned for a future migration);
    // emit NULL until then and the summary leaves Option::None.
    let list_sql = format!(
        "SELECT simulation_id, model_id, simulation_type, \
                status, domain \
           FROM simulations \
          WHERE {} \
          ORDER BY {} \
          LIMIT $1 OFFSET $2",
        where_sql,
        sort_fragment(sort),
    );
    let count_sql = format!(
        "SELECT COUNT(*) FROM simulations WHERE {}",
        // count's param indices are shifted by 2 (no limit/offset). Rebuild
        // the same where clause but starting at $1 instead of $3.
        rebase_where_indices(&where_sql, -2),
    );

    // Bind filter values to both queries in the same order we appended them.
    let mut q = sqlx::query_as::<_, (i64, String, String, String, String)>(&list_sql)
        .bind(limit)
        .bind(offset);
    if let Some(uid) = uid_opt { q = q.bind(uid); }
    if let Some(ref s) = filter_status { q = q.bind(s); }
    if let Some(ref d) = filter_domain { q = q.bind(d); }
    if let Some(ref m) = filter_model  { q = q.bind(m); }
    let rows = q.fetch_all(&p).await.ok()?;

    let mut qc = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(uid) = uid_opt { qc = qc.bind(uid); }
    if let Some(ref s) = filter_status { qc = qc.bind(s); }
    if let Some(ref d) = filter_domain { qc = qc.bind(d); }
    if let Some(ref m) = filter_model  { qc = qc.bind(m); }
    let total: i64 = qc.fetch_one(&p).await.ok()?;

    Some((
        rows.into_iter()
            .map(|(sid, mid, stype, status, domain)| SimulationSummary {
                simulation_id: sid as u64,
                model_id:      mid,
                simulation_type: match stype.as_str() {
                    "Outage" => crate::routes::SimulationType::Outage,
                    _        => crate::routes::SimulationType::Powerflow,
                },
                status: if status.is_empty() { None } else { Some(status) },
                domain: match domain.as_str() {
                    "SP"  => Some(crate::routes::DomainType::SP),
                    "DP"  => Some(crate::routes::DomainType::DP),
                    "EMT" => Some(crate::routes::DomainType::EMT),
                    _     => None,
                },
                // engine column not in PG schema yet — populated in a
                // future migration. For now `engine` on the summary is
                // always None; per-sim GET still carries it.
                engine: None,
            })
            .collect(),
        total,
    ))
}

/// Shift `$N` placeholders in a WHERE clause by `delta` so the same
/// fragment works in the list query (params start at $3) and the count
/// query (params start at $1). Negative delta moves indices down.
fn rebase_where_indices(sql: &str, delta: i32) -> String {
    // Simple single-pass rewriter: match `$<digits>` and replace with
    // `$<digits + delta>`. Good enough for our controlled input.
    let mut out = String::with_capacity(sql.len());
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '$' && i + 1 < bytes.len() && bytes[i+1].is_ascii_digit() {
            out.push('$');
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            let n: i32 = std::str::from_utf8(&bytes[start..end]).unwrap().parse().unwrap();
            out.push_str(&(n + delta).to_string());
            i = end;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Mark a simulation canceled in PG (v1.1.3). Best-effort; the real source
/// of truth for cancelation is the redis `sim:<id>:canceled` flag that the
/// worker consults — this PG write just keeps GET /simulation/<id> in sync
/// without waiting for the worker to process its next dequeue.
pub async fn mark_canceled(sim_id: u64) -> Result<(), sqlx::Error> {
    let Some(p) = pool().await else { return Ok(()) };
    sqlx::query(
        "UPDATE simulations
            SET status = 'canceled', completed_at = now()
          WHERE simulation_id = $1
            AND status IN ('queued', 'running')",
    )
    .bind(sim_id as i64)
    .execute(&p)
    .await?;
    Ok(())
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
