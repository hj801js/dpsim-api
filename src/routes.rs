use rocket::response::{self, Redirect, Responder, Response};
use rocket::serde::json::{Json};
use async_global_executor::block_on;
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
    pub trace_id:          String
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

impl Default for SimulationType {
    fn default() -> Self {
        SimulationType::Powerflow
    }
}

#[doc = "String conversion for the various Simulation types"]
impl SimulationType {
    fn to_string(&self) -> String {
        match &*self {
            SimulationType::Powerflow => "Powerflow".to_owned(),
            SimulationType::Outage    => "Outage".to_owned()
        }
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
    pub finaltime:         u64
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
        trace_id:        trace_id
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

type SimulationResult = std::result::Result<Json<Simulation>, SimulationError>;

impl<'r> Responder<'r, 'static> for SimulationError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        // Convert object to json
        let body = serde_json::to_string(&self).unwrap();
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
#[doc = "Liveness probe — returns 200 \"ok\" when the HTTP handler is reachable. \
         Intended for Makefile/container readiness checks. Upgrade to a real \
         readiness probe (redis + AMQP) when ops needs it."]
#[get("/healthz")]
pub async fn get_healthz() -> &'static str {
    "ok"
}

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
                    std::str::from_utf8(&boxed_data).unwrap().into()
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
#[doc = "Struct for encapsulation Simulation details"]
pub struct SimulationArray {
    pub simulations: Vec<SimulationSummary>
}

#[doc = "List the simulations"]
#[openapi]
#[get("/simulation", format="application/json")]
pub async fn get_simulations(user: MaybeAuthedUser) -> Result<Json<SimulationArray>, SimulationError> {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }
    // Prefer PG (survives redis flush, supports per-user filtering). Fall
    // back to the legacy redis scan when PG is off or the query fails.
    let user_sub = user.0.as_ref().map(|c| c.sub.as_str());
    if let Some(summaries) = pg::list_recent(100, user_sub).await {
        return Ok(Json(SimulationArray { simulations: summaries }));
    }
    match db::get_number_of_simulations() {
        Ok(number_of_simulations) => {
            let mut simvec = Vec::new();
            // "The range start..end contains all values with start <= x < end. It is empty if start >= end."
            // from https://doc.rust-lang.org/std/ops/struct.Range.html
            let last_plus_one = number_of_simulations+1;
            for n in 1..last_plus_one {
                match db::read_simulation(n) {
                    Ok(sim) => {
                        let sim_summary = SimulationSummary {
                            simulation_id:     sim.simulation_id,
                            model_id:          sim.model_id,
                            simulation_type:   sim.simulation_type,
                        };
                        simvec.push(sim_summary);
                    }
                    Err(e) => return Err( SimulationError { err: format!("Could not read simulation {} from redis DB: {}", n, e), http_status_code: Status::UnprocessableEntity} )
                }
            }
            let simarray = SimulationArray {
                simulations: simvec,
            };
            Ok(Json(simarray))
        },
        Err(e) => Err( SimulationError { err: format!("Could not read number of simulations from redis DB: {}", e), http_status_code: Status::UnprocessableEntity} )
    }
}

#[doc = "Create a new simulation"]
#[openapi]
#[post("/simulation", format = "application/json", data = "<form>")]
pub async fn post_simulation(user: MaybeAuthedUser, form: Json<SimulationForm > ) -> SimulationResult {
    if auth_required() && user.0.is_none() {
        return Err(SimulationError {
            err: "authentication required".into(),
            http_status_code: Status::Unauthorized,
        });
    }
    let user_sub = user.0.as_ref().map(|c| c.sub.clone());
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
            let amqp_sim         = AMQPSimulation::from_simulation(&simulation, model_url, load_profile_url);
            match block_on(amqp::request_simulation(&amqp_sim, &simulation.trace_id)) {
                Ok(()) => Ok(simulation),
                Err(e) => Err(SimulationError {
                    err: format!("Could not publish to amqp server: {}", e),
                    http_status_code: Status::BadGateway
                })
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

#[doc = "Returns the list of routes that we have defined"]
pub fn get_routes() -> Vec<rocket::Route>{
    return rocket_okapi::openapi_get_routes![ get_root, get_api, get_healthz, get_version, get_simulations, post_simulation, post_model, get_simulation_id]
}
