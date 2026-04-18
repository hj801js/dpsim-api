//!
//! # DPSIM Service Rest API for controlling DPSim analyzer
//! Author : Richard Marston <rmarston@eonerc.rwth-aachen.de>
//!
//! ## Table of endpoints
//!
//! | Endpoint                    | Method | Description        | Implementation              | Parameters                      | Returns                |
//! |-----------------------------|--------|--------------------|-----------------------------|---------------------------------|------------------------|
//! | /simulation                 | POST   | Add a simulation   | [`post_simulation`][post_s] | [`SimulationForm`][s_f_s]       | [`Simulation`][sim]    |
//! | /simulation                 | GET    | List simulations   | [`get_simulations`][get_s]  | None                            | [ [`Simulation`][sim] ]|
//! | /simulation/ \[id]          | GET    | Simulation details | [`todo!`]                   | None                            | [`Simulation`][sim]    |
//! | /simulation/ \[id] /results | GET    | Simulation results | [`todo!`]                   | None                            | plain text             |
//! | /simulation/ \[id] /logs    | GET    | Simulation logs    | [`todo!`]                   | None                            | plain text             |
//! | /debug                      | GET    | DPsim-api debug    | [`todo!`]                   | None                            | plain text             |
//!
//! [post_s]: routes::post_simulation()
//! [get_s]: routes::get_simulations()
//! [s_f_s]: routes::SimulationForm
//! [sim]: routes::Simulation

// stop rustdoc complaining that I'm linking
// to the routes module, which is privately
// owned by this one (main.rs)
#![allow(rustdoc::private_intra_doc_links)]

#[macro_use]
extern crate rocket;

mod routes;
mod file_service;
mod amqp;
mod auth;
mod pg;
mod telemetry;
#[cfg(not(test))] mod db;
use rocket_dyn_templates::Template;
use rocket_okapi::swagger_ui::{make_swagger_ui, SwaggerUIConfig};
use rocket_prometheus::PrometheusMetrics;

fn get_docs() -> SwaggerUIConfig {
    SwaggerUIConfig {
        url: "/openapi.json".to_string(),
        ..Default::default()
    }
}

#[rocket::main]
#[doc = "The main entry point for Rocket" ]
async fn main() -> Result <(), rocket::Error> {

    if telemetry::init() {
        eprintln!("[otel] exporting spans to {}",
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_default());
    }

    // Rocket 0.5 stable returns the launched Rocket<Ignite> on successful
    // shutdown instead of (). Discard it to keep the main() signature.
    // rocket_prometheus exposes /metrics with default HTTP histograms.
    let prometheus = PrometheusMetrics::new();
    rocket::build()
        .register("/", catchers![routes::incomplete_form])
        .mount("/", routes::get_routes())
        .mount("/", auth::get_routes())
        .mount("/swagger", make_swagger_ui(&get_docs()))
        .mount("/metrics", prometheus.clone())
        .attach(prometheus)
        .attach(Template::fairing())
        .launch()
        .await
        .map(|_| ())
}

#[cfg(test)]
mod db {
    use redis::RedisResult;
    use crate::routes::{Simulation, SimulationType};
    use crate::routes::{DomainType, SolverType};
    pub fn get_number_of_simulations() -> RedisResult<u64> {
        Ok(10)
    }
    pub fn get_new_simulation_id() -> RedisResult<u64> {
        Ok(1)
    }
    pub fn write_simulation(_key: &String, _value: &Simulation) -> redis::RedisResult<()> {
        Ok(())
    }
    pub fn read_simulation(_key: u64) -> redis::RedisResult<Simulation> {
        Ok(Simulation {
               error:           "".to_owned(),
               load_profile_id: "".into(),
               model_id:        "1".to_string(),
               results_id:      "1".to_string(),
               results_data:    "1".to_string(),
               simulation_id:   1,
               simulation_type: SimulationType::Powerflow,
               domain:          DomainType::SP,
               solver:          SolverType::NRP,
               timestep:        1,
               finaltime:       360,
               trace_id:        "".into()
        })
    }
}
#[cfg(test)]
mod tests;
