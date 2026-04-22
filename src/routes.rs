use rocket::response::{self, Redirect, Responder, Response};
use rocket::serde::json::{Json};
use crate::db;
use crate::amqp;
use crate::amqp::AMQPSimulation;
use crate::auth::{auth_required, MaybeAuthedUser};
use crate::pg;
use rocket_dyn_templates::{Template};
use std::{ str, fmt };
use rocket_okapi::{ openapi, OpenApiError,
                    response::OpenApiResponderInner,
                    gen::OpenApiGenerator };
use okapi::openapi3::Responses;
use serde::{ Serialize, Deserialize };
use rocket::http::{ContentType, Status};
use rocket::{Request};
use schemars::JsonSchema;
use crate::file_service;
use http::uri::InvalidUri as InvalidUri;
use log::info;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[doc = "Struct for encapsulation Simulation details"]
pub struct Simulation {
    pub error: String,
    pub load_profile_id:   String,
    pub model_id:          String,
    pub results_id:        String,
    pub results_data:      String,
    pub simulation_id:     u64,
    pub simulation_type:   SimulationType,
    pub domain:            DomainType,
    pub solver:            SolverType,
    pub timestep:          u64,
    pub finaltime:         u64,
    #[serde(default)]
    pub trace_id:          String,
    #[serde(default)]
    pub engine:            EngineType,
}

impl fmt::Display for Simulation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}, {})", self.simulation_id, self.simulation_type, self.model_id)
    }
}

impl fmt::Display for SimulationSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}, {})", self.simulation_id, self.simulation_type, self.model_id)
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SimulationSummary {
    pub simulation_id:     u64,
    pub model_id:          String,
    pub simulation_type:   SimulationType,
}

#[doc = "Enum for the various Simulation types"]
#[derive(JsonSchema, FromFormField, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SimulationType {
    Powerflow,
    Outage
}

impl fmt::Display for SimulationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[doc = "Enum for the various Simulation types"]
#[derive(JsonSchema, FromFormField, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum DomainType {
    SP,
    DP,
    EMT
}

#[doc = "Enum for the various Solver types"]
#[derive(JsonSchema, FromFormField, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SolverType {
    MNA,
    DAE,
    NRP
}

#[doc = "Simulation engine selection (Phase 4 dual-engine UX).

dpsim      — native DP/EMT/SP simulator (default, backward compatible).
pandapower — CIM → pp.runpp() steady-state only, much faster for PF.
both       — runs pandapower first (quick reference) then dpsim; UI can
             diff the two CSVs."]
#[derive(JsonSchema, FromFormField, Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum EngineType {
    #[serde(rename = "dpsim")]
    Dpsim,
    #[serde(rename = "pandapower")]
    Pandapower,
    #[serde(rename = "both")]
    Both,
}

impl Default for EngineType {
    fn default() -> Self { EngineType::Dpsim }
}

impl Default for SimulationType {
    fn default() -> Self {
        SimulationType::Powerflow
    }
}


/// # Form for submitting a new Simulation
///
/// ## Parameters:
/// * simulation_type
///   - String
///   - must be one of "Powerflow", "Outage"
/// * load_profile_id
///   - String
///   - must be a valid id that exists in the associated sogno file service
/// * model_id
///   - String
///   - must be a valid id that exists in the associated sogno file service
#[derive(FromForm, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SimulationForm {
    pub simulation_type:   SimulationType,
    pub model_id:          String,
    pub load_profile_id:   String,
    #[field(default = DomainType::SP)]
    pub domain:            DomainType,
    #[field(default = SolverType::NRP)]
    pub solver:            SolverType,
    #[field(default = 1)]
    pub timestep:          u64,
    #[field(default = 30)]
    pub finaltime:         u64,
    /// Optional — name (mRID or name attribute) of a CIM ACLineSegment to
    /// remove before sim.run(). Leave empty / None for a baseline simulation.
    /// P3.4 outage MVP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outage_component:  Option<String>,
    /// Optional — multiplier applied to every CIM EnergyConsumer P/Q before
    /// sim.run(). 1.0 = baseline, 1.5 = heavier load, 0.5 = lighter. Worker
    /// mutates the SV file so CIMReader sees the scaled values.
    /// P3.3 load-profile MVP (scalar, not time-series).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_factor:       Option<f64>,
    /// Optional — time-series variant of load_factor. Each point is
    /// [t_sec, factor]; worker picks an effective scalar (max for
    /// Powerflow stress-tests, linearly-interpolated end-of-run value
    /// for DP/EMT) and applies it with _apply_load_factor. Per-step
    /// time-stepping isn't exposed by dpsim's Python API so this is a
    /// pragmatic approximation — see docs/44 §X for the scope note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_factor_series: Option<Vec<LoadFactorPoint>>,
    /// Simulation engine (Phase 4). dpsim is backward-compatible default.
    /// `pandapower` runs pp.runpp() via the PISA adapter; `both` runs
    /// pp first then dpsim so the UI can compare the two. The worker
    /// dispatches on `parameters.engine` in the AMQP payload.
    #[serde(default)]
    #[field(default = EngineType::Dpsim)]
    pub engine: EngineType,
}

#[derive(FromForm, Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct LoadFactorPoint {
    pub t_sec:  f64,
    pub factor: f64,
}

async fn parse_simulation_form(
    form: Json<SimulationForm>,
    user_sub: Option<&str>,
) -> Result<Json<Simulation>, SimulationError>{
    // Sanity-check numeric bounds before allocating a simulation id so the
    // caller gets a 400 instead of a row in redis + a queued job. The worker
    // clamps these too (examples/service-stack/worker.py::clamp_params), but
    // obviously-bad input should never reach the queue.
    if form.timestep == 0 {
        return Err(SimulationError {
            err: "timestep (ms) must be > 0".into(),
            http_status_code: Status::BadRequest,
        });
    }
    if form.finaltime < form.timestep.saturating_mul(10) {
        return Err(SimulationError {
            err: format!(
                "finaltime ({} ms) must be >= 10 * timestep ({} ms)",
                form.finaltime, form.timestep,
            ),
            http_status_code: Status::BadRequest,
        });
    }

    let simulation_id = match db::get_new_simulation_id() {
        Ok(id) => id,
        Err(e) => return Err(SimulationError {
                             err: format!("Failed to obtain new simulation id: {}", e),
                             http_status_code: Status::BadGateway
                         })
    };
    let results_file     = file_service::create_results_file().await?;
    // Short hex trace id — enough to correlate a UI submission with worker
    // log lines without being a hard guarantee of uniqueness across history.
    let trace_id = {
        use rand::RngCore;
        let mut b = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut b);
        b.iter().map(|x| format!("{:02x}", x)).collect::<String>()
    };
    let simulation = Simulation {
        error:           "".to_string(),
        load_profile_id: form.load_profile_id.clone(),
        model_id:        form.model_id.clone(),
        results_id:      results_file,
        results_data:    "".into(),
        simulation_id:   simulation_id,
        simulation_type: form.simulation_type,
        domain:          form.domain,
        solver:          form.solver,
        timestep:        form.timestep,
        finaltime:       form.finaltime,
        trace_id:        trace_id,
        engine:          form.engine,
    };
    match db::write_simulation(&simulation_id.to_string(), &simulation) {
        Ok(()) => {
            // Best-effort mirror to PG. Errors logged, never propagated —
            // redis remains authoritative until the PG flip-over lands.
            if let Err(e) = pg::insert_simulation(&simulation, user_sub).await {
                info!("pg mirror failed (continuing on redis only): {}", e);
            }
            Ok(Json(simulation))
        },
        Err(e) => Err(SimulationError {
                      err: format!("Could not write to db: {}", e.to_string()),
                      http_status_code: Status::BadGateway
                  })
    }
}

/// Error body emitted to HTTP clients. On the wire (v1.1+):
///
/// ```json
/// { "error": "<human message>", "code": "ERR_*", "err": "<alias>" }
/// ```
///
/// `error` is the canonical field. `err` is kept as an alias for one
/// release so v1.0-era clients that parsed the old `{"err": ...}` shape
/// don't break overnight — removed in v1.2.
///
/// `code` is a stable machine-readable enum value so clients can branch
/// on error type without string-matching the message. Classified from
/// http_status_code + route context at Responder time.
///
/// The Rust struct itself retains the original `{err, http_status_code}`
/// layout so existing struct-literal callers still compile; the extended
/// JSON shape is assembled in `respond_to`.
#[derive(Debug, Default, serde::Serialize, schemars::JsonSchema)]
pub struct SimulationError {
    pub err: String,
    #[serde(skip)]
    pub http_status_code: rocket::http::Status,
}

impl From<hyper::Error> for SimulationError {
    fn from(input: hyper::Error) -> Self {
        return SimulationError { err: format!("Error converting url: {}", input), http_status_code: rocket::http::Status{ code: 500 } }
    }
}

impl From<InvalidUri> for SimulationError {
    fn from(input: InvalidUri) -> Self {
        return SimulationError { err: format!("Error converting uri: {}", input), http_status_code: rocket::http::Status{ code: 500 } }
    }
}

fn default_code_for(status: rocket::http::Status) -> &'static str {
    match status.code {
        400 => "ERR_BAD_REQUEST",
        401 => "ERR_UNAUTHORIZED",
        403 => "ERR_FORBIDDEN",
        404 => "ERR_NOT_FOUND",
        409 => "ERR_CONFLICT",
        413 => "ERR_PAYLOAD_TOO_LARGE",
        422 => "ERR_UNPROCESSABLE",
        429 => "ERR_RATE_LIMITED",
        502 => "ERR_UPSTREAM",
        503 => "ERR_UNAVAILABLE",
        500 | _ => "ERR_INTERNAL",
    }
}

type SimulationResult = std::result::Result<Json<Simulation>, SimulationError>;

impl<'r> Responder<'r, 'static> for SimulationError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        // v1.1 canonical shape: {error, code, err}. `err` is a deprecated
        // alias for one release; remove in v1.2. `code` is derived from
        // the HTTP status for a consistent machine-readable tag.
        let code = default_code_for(self.http_status_code);
        let body = serde_json::json!({
            "error": &self.err,
            "code":  code,
            "err":   &self.err,
        }).to_string();
        let len = body.len();
        Response::build()
            .sized_body(len, std::io::Cursor::new(body))
            .header(ContentType::JSON)
            .status(self.http_status_code)
            .ok()
    }
}

impl OpenApiResponderInner for SimulationError {
    fn responses(_gen: &mut OpenApiGenerator) -> Result<Responses, OpenApiError> {
        Ok(Responses::default())
    }
}

#[doc = "A struct used for sharing info about a route with a template"]
#[derive(Serialize, Clone)]
struct Route {
    collapse_id: String,
    heading_id: String,
    link: String,
    method: String,
    name: String,
    path: String
}

#[derive(Serialize)]
#[doc = "A struct used for sharing info about some routes with a template"]
struct RoutesContext {
    routes: Vec<Route>
}

#[doc = "List the endpoints"]
#[openapi(skip)]
#[get("/api", format = "text/html")]
pub async fn get_api() -> Template {
    let mut routes = [].to_vec();
    for (index, fn_name) in get_routes().iter().enumerate() {
        let heading_id  = format!("heading{}", index);
        let collapse_id  = format!("collapse{}", index);
        let name = match &fn_name.name {
            Some(x) => x.to_string(),
            None => "".to_string()
        };
        let route_json = Route {
            collapse_id: collapse_id,
            heading_id: heading_id,
            link: document_link(&name),
            method: fn_name.method.to_string(),
            name: name,
            path: fn_name.uri.path().to_string(),
        };
        routes.push(route_json);
    }
    let context = RoutesContext{ routes: routes };
    Template::render("api", &context)
}

#[openapi(skip)]
#[ doc = "Redirects to /api" ]
#[get("/", format = "text/html")]
pub async fn get_root() -> Redirect {
    Redirect::to(uri!(get_api))
}

#[openapi(skip)]
#[doc = "Liveness probe — returns 200 \"ok\" when the HTTP handler is reachable.\
         Doesn't check downstream dependencies: use /readyz for that."]
#[get("/healthz")]
pub async fn get_healthz() -> &'static str {
    "ok"
}

/// Body of /readyz so each component's state is machine-readable.
#[derive(Serialize, JsonSchema)]
pub struct ReadyzResponse {
    pub ready:    bool,
    pub redis:    bool,
    pub postgres: bool,
    pub amqp:     bool,
}

#[doc = "Readiness probe — returns 200 only when all critical dependencies \
         are reachable: redis (rate-limit + sim store), PG (audit log + user \
         store; skipped when DATABASE_URL unset), and AMQP (worker queue). \
         Returns 503 with the per-component breakdown when any check fails. \
         Point kubernetes readinessProbe at this instead of /healthz."]
#[openapi]
#[get("/readyz")]
pub async fn get_readyz() -> (Status, Json<ReadyzResponse>) {
    // Redis: ping via rate-limit hit on a throwaway bucket. Cheap, avoids
    // a second helper and exercises the Lua-script path we care about.
    let redis_ok = db::rate_limit_hit("readyz_probe", 5).is_some();

    // Postgres: None pool = DATABASE_URL unset, which means PG is
    // explicitly disabled — treat as "not required" rather than failure
    // so single-node deployments without PG stay ready.
    let pg_ok = match pg::pool().await {
        Some(p) => sqlx::query("SELECT 1").execute(&p).await.is_ok(),
        None    => true,
    };

    // AMQP: cheap Connection::connect() + close. Reuses the same env var
    // as the publish path so the check and the real work agree on target.
    let amqp_ok = amqp_reachable().await;

    let ready = redis_ok && pg_ok && amqp_ok;
    let body = ReadyzResponse {
        ready,
        redis:    redis_ok,
        postgres: pg_ok,
        amqp:     amqp_ok,
    };
    let status = if ready { Status::Ok } else { Status::ServiceUnavailable };
    (status, Json(body))
}

#[cfg(not(test))]
async fn amqp_reachable() -> bool {
    let addr = std::env::var("AMQP_ADDR")
        .unwrap_or_else(|_| "amqp://rabbitmq:5672/%2f".into());
    match lapin::Connection::connect(
        &addr,
        lapin::ConnectionProperties::default().with_default_executor(1),
    ).await {
        Ok(conn) => {
            let _ = conn.close(200, "readyz").await;
            true
        }
        Err(_) => false,
    }
}

// Tests never have AMQP running; pretend the broker is up so test_healthz
// stays as a pure HTTP probe. Realness checked in non-test builds.
#[cfg(test)]
async fn amqp_reachable() -> bool { true }

#[openapi(skip)]
#[doc = "Version probe — returns build-time package version + short git SHA so \
         deployments can be pinpointed. SHA is injected by build.rs; falls back \
         to \"unknown\" for builds outside a git checkout."]
#[get("/version")]
pub async fn get_version() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name":    env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": env!("DPSIM_API_GIT_SHA"),
    }))
}

#[doc = "Get the details for a simulation"]
#[openapi]
#[get("/simulation/<id>", format="application/json")]
pub async fn get_simulation_id(id: u64) -> SimulationResult {
    match db::read_simulation(id) {
        Ok(mut sim) => {
            let uri: String = match file_service::convert_id_to_url(&sim.results_id).await {
                Ok(url) => url,
                Err(e) => return Err( SimulationError {
                                          err: format!("Could not read convert results id to url. Results id:{} Error: {}", sim.results_id, e),
                                          http_status_code: Status::Unauthorized
                                      })
            };
            let data = file_service::get_data_from_url(&uri).await;
            let results: String = match data {
                Ok(boxed_data) => {
                    // Use from_utf8_lossy so a stray invalid byte in the CSV
                    // doesn't panic the handler. dpsim CSV is ASCII in
                    // practice; lossy conversion is a strictly-safer fallback.
                    String::from_utf8_lossy(&boxed_data).into_owned()
                },
                Err(e) => return Err( SimulationError {
                                          err: format!("Could not read results from url. Results id:{} Error: {}", sim.results_id, e),
                                          http_status_code: Status::Unauthorized
                                      })
            };
            sim.results_data = results;
            Ok(Json(sim))
        },
        Err(e) =>  Err( SimulationError { err: e.to_string(), http_status_code: Status::UnprocessableEntity } )
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[doc = "Paged list of simulations.

`total` is the full count available on the server (useful for paging UI);
`limit` + `offset` echo back the effective query (may be clamped from the
request)."]
pub struct SimulationArray {
    pub simulations: Vec<SimulationSummary>,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

// Pagination defaults + clamps. Default 50 matches what the Next.js UI
// already renders per page; max 500 is high enough for export scripts
// without risking a 1M-row scan.
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 500;

#[doc = "List simulations. Pagination via `?limit=N&offset=N` (default 50, \
         max 500). Optional filters: `?status=queued|running|done|failed|canceled`, \
         `?domain=SP|DP|EMT`, `?model_id=<id>`. Filters require PG — they \
         are ignored on the redis fallback path."]
#[openapi]
#[get("/simulation?<limit>&<offset>&<status>&<domain>&<model_id>", format="application/json")]
pub async fn get_simulations(
    user: MaybeAuthedUser,
    limit: Option<u32>,
    offset: Option<u32>,
    status: Option<String>,
    domain: Option<String>,
    model_id: Option<String>,
) -> Result<Json<SimulationArray>, SimulationError> {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }
    let lim = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let off = offset.unwrap_or(0);
    let filters = pg::ListFilters { status, domain, model_id };

    // Prefer PG (survives redis flush, supports per-user filtering + offset).
    // Fall back to the legacy redis scan when PG is off or the query fails.
    let user_sub = user.0.as_ref().map(|c| c.sub.as_str());
    if let Some((summaries, total)) = pg::list_recent(lim as i64, off as i64, user_sub, &filters).await {
        return Ok(Json(SimulationArray {
            simulations: summaries,
            total: total.max(0) as u64,
            limit: lim,
            offset: off,
        }));
    }

    // Redis fallback: paginate in-memory since redis doesn't index by date.
    // Newest simulation_id is the largest (INCR-counter), so walk descending
    // and skip `offset` rows, take `limit`.
    match db::get_number_of_simulations() {
        Ok(total_n) => {
            let mut simvec = Vec::new();
            let mut seen: u32 = 0;
            let mut n = total_n;
            while n >= 1 && simvec.len() < lim as usize {
                if let Ok(sim) = db::read_simulation(n) {
                    if seen >= off {
                        simvec.push(SimulationSummary {
                            simulation_id:   sim.simulation_id,
                            model_id:        sim.model_id,
                            simulation_type: sim.simulation_type,
                        });
                    }
                    seen += 1;
                }
                if n == 0 { break; }
                n -= 1;
            }
            Ok(Json(SimulationArray {
                simulations: simvec,
                total: total_n,
                limit: lim,
                offset: off,
            }))
        },
        Err(e) => Err( SimulationError {
            err: format!("Could not read number of simulations from redis DB: {}", e),
            http_status_code: Status::UnprocessableEntity,
        })
    }
}

#[doc = "Create a new simulation"]
#[openapi]
#[post("/simulation", format = "application/json", data = "<form>")]
pub async fn post_simulation(
    user: MaybeAuthedUser,
    req_span: crate::telemetry::RequestSpanCtx,
    form: Json<SimulationForm>,
) -> SimulationResult {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }
    let user_sub = user.0.as_ref().map(|c| c.sub.clone());
    // Pull the scenario hints off the form before we move it into the parser.
    let form_outage = form.outage_component.clone();
    let form_load_factor = form.load_factor;
    let form_load_series = form.load_factor_series.clone();
    match parse_simulation_form(form, user_sub.as_deref()).await {
        Ok(simulation) => {
            let model_id         = &simulation.model_id;
            let load_profile_id  = &simulation.load_profile_id;
            let model_url        = file_service::convert_id_to_url(model_id).await?;
            let mut load_profile_url = "".into();
            let none_string: String = "None".into();
            info!("load_profile_id: {}", load_profile_id);
            if simulation.load_profile_id != none_string {
                info!("Converting {} to url", simulation.load_profile_id);
                load_profile_url = file_service::convert_id_to_url(load_profile_id).await?;
            }
            let outage           = form_outage.clone();
            let amqp_sim         = AMQPSimulation::from_simulation(
                &simulation, model_url, load_profile_url, outage,
                form_load_factor, form_load_series,
            );
            // P2.2d — reuse the fairing's request span context so AMQP
            // publishes land in the same trace Jaeger already knows about.
            // Falls back to a fresh span when OTel isn't initialised.
            let span_ctx         = req_span.0.clone()
                .or_else(crate::telemetry::start_post_simulation_span);
            let traceparent      = span_ctx.as_ref()
                .and_then(crate::telemetry::span_context_to_traceparent);
            let actor = user_sub.as_deref()
                .map(|s| format!("user:{}", s))
                .unwrap_or_else(|| "anon".into());
            let target = format!("sim:{}", simulation.simulation_id);
            let trace_id = simulation.trace_id.clone();
            match amqp::request_simulation_with_traceparent(
                &amqp_sim, &simulation.trace_id, traceparent,
            ).await {
                Ok(()) => {
                    crate::pg::audit(
                        &actor, "sim.submit", Some(&target), "success",
                        Some(&trace_id), None,
                        Some(serde_json::json!({
                            "model_id": simulation.model_id,
                            "engine": simulation.engine,
                            "domain": simulation.domain,
                        })),
                    ).await;
                    Ok(simulation)
                },
                Err(e) => {
                    crate::pg::audit(
                        &actor, "sim.submit", Some(&target), "failure",
                        Some(&trace_id), None,
                        Some(serde_json::json!({ "error": format!("{}", e) })),
                    ).await;
                    Err(SimulationError {
                        err: format!("Could not publish to amqp server: {}", e),
                        http_status_code: Status::BadGateway
                    })
                }
            }
        },
        Err(e) => Err(e)
    }
}

#[derive(Serialize, JsonSchema)]
pub struct ModelUploadResponse {
    pub model_id: String,
    pub bytes: usize,
}

/// Server-Sent Events stream of redis-backed simulation status.
///
/// Emits one event per status change (or at most once every poll tick),
/// closes when status reaches a terminal state (done/failed/canceled)
/// or after a 30-minute idle timeout. Heartbeat comments every 15s keep
/// the connection alive through intermediary proxies.
///
/// Event data: JSON mirror of `/api/sim-status/<id>` response:
/// `{"status": "...", "progress": 0-100, "error": "..." | null, ...}`.
///
/// Usage from a browser:
/// ```js
/// const es = new EventSource('/simulation/123/events');
/// es.onmessage = e => console.log(JSON.parse(e.data));
/// ```
#[doc(hidden)]
#[get("/simulation/<id>/events")]
pub async fn get_simulation_events(
    id: u64,
) -> rocket::response::stream::EventStream![rocket::response::stream::Event] {
    use rocket::response::stream::{Event, EventStream};
    use rocket::tokio::time::{sleep, Duration, Instant};

    EventStream! {
        let deadline = Instant::now() + Duration::from_secs(30 * 60);
        let mut last_payload: Option<String> = None;
        // Poll the redis sidechannel. This is intentionally simple — a
        // real pub/sub path would avoid the poll but adds more moving
        // parts than v1.1 needs.
        loop {
            if Instant::now() >= deadline {
                yield Event::data("timeout").event("closed");
                break;
            }

            // 1) Cancelation flag (terminal)
            let canceled = db::is_sim_canceled(id);
            // 2) Current status (Option<String> JSON from redis, or None)
            let status_json = read_sim_status_json(id);

            let mut status_str = String::from("unknown");
            if let Some(ref s) = status_json {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                    if let Some(st) = v.get("status").and_then(|x| x.as_str()) {
                        status_str = st.to_string();
                    }
                }
            }
            if canceled && status_str != "done" && status_str != "failed" {
                status_str = "canceled".into();
            }

            let merged = serde_json::json!({
                "simulation_id": id,
                "status": status_str,
                "payload": status_json.as_deref()
                                       .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
                "canceled": canceled,
            }).to_string();

            // Only emit when payload changed (deduplicate reconnect spam)
            if last_payload.as_deref() != Some(&merged) {
                yield Event::data(merged.clone()).event("status");
                last_payload = Some(merged);
            }

            if matches!(status_str.as_str(), "done" | "failed" | "canceled") {
                yield Event::data(status_str.clone()).event("closed");
                break;
            }

            sleep(Duration::from_millis(500)).await;
        }
    }
}

/// Small redis helper for SSE: return the raw JSON blob stored at
/// `dpsim:sim:<id>:status` (written by the worker's set_status path), or
/// None if unset / redis unreachable.
fn read_sim_status_json(id: u64) -> Option<String> {
    use redis::Commands;
    let url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://redis-master/".into());
    let client = redis::Client::open(url).ok()?;
    let mut conn = client.get_connection().ok()?;
    let key = format!("dpsim:sim:{}:status", id);
    conn.get::<_, String>(&key).ok()
}

/// Response body for POST /simulation/<id>/cancel.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CancelResponse {
    pub simulation_id: u64,
    pub canceled: bool,
    pub status: String,
}

#[doc = "Cancel a simulation. \
\
Sets a redis flag `sim:<id>:canceled` that the worker checks before \
starting work. For queued jobs the worker acks the AMQP message and \
moves on. For already-running jobs the cancel is best-effort — the \
current sim.run() can't be interrupted mid-step, but the post-run \
logging path skips uploading results when the flag is set. \
\
Idempotent: calling twice returns the same response."]
#[openapi]
#[post("/simulation/<id>/cancel")]
pub async fn post_cancel_simulation(
    user: MaybeAuthedUser,
    id: u64,
) -> Result<Json<CancelResponse>, SimulationError> {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }

    // Verify the sim exists before accepting cancel — 404 is clearer than
    // "cancel flag set on a non-existent id".
    if db::read_simulation(id).is_err() {
        return Err(SimulationError {
            err: format!("simulation {} not found", id),
            http_status_code: Status::NotFound,
        });
    }

    let ok = db::mark_sim_canceled(id);
    if !ok {
        return Err(SimulationError {
            err: "redis unavailable; cannot persist cancel flag".into(),
            http_status_code: Status::ServiceUnavailable,
        });
    }

    // Best-effort PG update so GET /simulation shows 'canceled' quickly
    // rather than waiting for the worker to process its next dequeue.
    let _ = crate::pg::mark_canceled(id).await;

    let actor = user.0.as_ref()
        .map(|c| format!("user:{}", c.sub))
        .unwrap_or_else(|| "anon".into());
    crate::pg::audit(
        &actor, "sim.cancel", Some(&format!("sim:{}", id)),
        "success", None, None, None,
    ).await;

    Ok(Json(CancelResponse {
        simulation_id: id,
        canceled: true,
        status: "canceled".into(),
    }))
}

#[openapi(skip)]
#[doc = "Upload a CIM model (raw bytes in the request body). Returns the \
         model_id the client should pass to POST /simulation. 16 MiB cap \
         enforced explicitly with 413 on overflow."]
#[post("/models", data = "<body>")]
pub async fn post_model(
    user: MaybeAuthedUser,
    body: rocket::data::Data<'_>,
) -> Result<Json<ModelUploadResponse>, SimulationError> {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }
    use rocket::data::ToByteUnit;
    // 16 MiB — enough for IEEE-39 CIM bundles (typically a few hundred KB to
    // a few MB). Over this we 413 rather than silently truncating.
    let bytes = body.open(16_u32.mebibytes())
        .into_bytes()
        .await
        .map_err(|e| SimulationError {
            err: format!("failed to read upload body: {}", e),
            http_status_code: Status::PayloadTooLarge,
        })?;
    if !bytes.is_complete() {
        return Err(SimulationError {
            err: "upload exceeds 16 MiB limit".into(),
            http_status_code: Status::PayloadTooLarge,
        });
    }
    let bytes_vec = bytes.into_inner();
    let len = bytes_vec.len();
    // CIM XML validation — reject anything that isn't well-formed XML and
    // anything with a DOCTYPE declaration (entity expansion / billion-laughs
    // attack surface). ZIP bundles pass through unchecked; worker-side
    // _resolve_uploaded_model will sniff and extract them.
    if !looks_like_zip(&bytes_vec) {
        if let Err(e) = validate_cim_xml(&bytes_vec) {
            return Err(SimulationError {
                err: format!("CIM validation failed: {}", e),
                http_status_code: Status::BadRequest,
            });
        }
    }
    // CIM XML is the only format the worker accepts today; hard-code the
    // content type to text/xml when forwarding to file-service.
    let model_id = file_service::put_model_bytes(bytes_vec, "application/xml")
        .await
        .map_err(|e| SimulationError {
            err: format!("file-service upload failed: {}", e),
            http_status_code: Status::BadGateway,
        })?;
    info!("uploaded model {} ({} bytes)", model_id, len);
    Ok(Json(ModelUploadResponse { model_id, bytes: len }))
}

#[doc = "Create a link to the documentation page for the given function"]
fn document_link(fn_name: &str) -> String {
    format!("https://sogno-platform.github.io/dpsim-api/dpsim_api/routes/fn.{}{}", fn_name, ".html")
}

#[doc = "Handler for when an incomplete form has been submitted"]
#[catch(422)]
pub async fn incomplete_form(form: &rocket::Request<'_>) -> String {
    info!("FORM: {}", form);
    format!("Incomplete form.{}", form)
}

/// ZIP local-file-header magic. Byte-for-byte identical to the worker's
/// `body[:4] == b"PK\x03\x04"` sniff in `_resolve_uploaded_model` — both
/// sides must agree, otherwise an upload that passes API validation gets
/// rejected by the worker (or vice versa).
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

#[doc = "Returns the list of routes that we have defined"]
fn looks_like_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ZIP_MAGIC
}

/// Validate an uploaded CIM XML body. Returns `Ok` for well-formed XML
/// without a DOCTYPE. DOCTYPE is rejected outright: CIMpp doesn't need it
/// and leaving the door open invites XXE / billion-laughs.
fn validate_cim_xml(bytes: &[u8]) -> Result<(), String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    if bytes.is_empty() {
        return Err("empty body".into());
    }
    // CIM XML is UTF-8 (required by IEC 61970-552). Reject non-UTF-8 here
    // so we never feed a lossy conversion into the downstream worker.
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("invalid UTF-8 at byte {}: {}", e.valid_up_to(), e))?;

    // `Reader::from_str` is the slice-backed reader — no external buf
    // needed and events borrow directly from `text` instead of copying
    // through a Vec on every read.
    let mut reader = Reader::from_str(text);
    {
        let cfg = reader.config_mut();
        cfg.trim_text(true);
        cfg.check_end_names = true;  // reject <open>...<open2></open2> without closing <open>
        cfg.expand_empty_elements = false;
    }
    let mut saw_root = false;
    let mut depth: i32 = 0;
    loop {
        match reader.read_event() {
            Err(e) => return Err(format!("malformed XML at pos {}: {}", reader.buffer_position(), e)),
            Ok(Event::Eof) => break,
            // DOCTYPE processing instruction → entity expansion surface.
            // quick-xml surfaces these as DocType events; reject any presence.
            Ok(Event::DocType(dt)) => {
                return Err(format!(
                    "DOCTYPE declarations are not allowed (got {:?}); \
                     CIM files shipped with dpsim never use them",
                    std::str::from_utf8(dt.as_ref()).unwrap_or("<non-utf8>")
                ));
            }
            Ok(Event::Start(_)) => {
                saw_root = true;
                depth += 1;
            }
            Ok(Event::End(_)) => {
                depth -= 1;
            }
            Ok(Event::Empty(_)) => {
                saw_root = true;
            }
            _ => {}
        }
    }
    if !saw_root {
        return Err("no XML elements found".into());
    }
    if depth != 0 {
        return Err(format!("unbalanced elements (depth={} at EOF)", depth));
    }
    Ok(())
}


pub fn get_routes() -> Vec<rocket::Route>{
    // get_simulation_events lives outside the openapi macro because
    // rocket_okapi 0.8 doesn't know how to describe EventStream responses.
    let mut openapi = rocket_okapi::openapi_get_routes![
        get_root, get_api, get_healthz, get_readyz, get_version,
        get_simulations, post_simulation, post_cancel_simulation,
        post_model, get_simulation_id, crate::topology::get_topology
    ];
    openapi.extend(rocket::routes![get_simulation_events]);
    openapi
}
