#[cfg(not(test))]
use lapin::{
    options::*, publisher_confirm::Confirmation, types::FieldTable, BasicProperties, Connection,
    ConnectionProperties, Result,
};
#[cfg(not(test))]
use log::info;
#[cfg(test)]
use lapin::{
    Result,
};
use crate::routes::{Simulation, SimulationType, DomainType, SolverType};
use rocket::serde::json::{json, Json};
use serde::{ Serialize, Deserialize };
use schemars::JsonSchema;
#[cfg(test)]
pub async fn publish(bytes: Vec<u8>, _trace_id: &str) -> Result<()> {
    println!("AMQPSimulation: {:?}", bytes);
    Ok(())
}

/// Build a W3C traceparent string: `00-<trace>-<span>-01`. Trace id is our
/// short 12-hex id padded up to 32 hex with random bytes so it's still a
/// valid lookup key in Jaeger; span id is freshly random per publish.
fn _build_w3c_traceparent(trace_id: &str) -> String {
    use rand::RngCore;
    let mut trace_hex = trace_id.to_lowercase();
    trace_hex.retain(|c| c.is_ascii_hexdigit());
    if trace_hex.len() > 32 { trace_hex.truncate(32); }
    while trace_hex.len() < 32 {
        let mut b = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut b);
        trace_hex.push_str(&format!("{:02x}", b[0]));
        if trace_hex.len() > 32 { trace_hex.truncate(32); }
    }
    // W3C forbids all-zero trace/span ids; guard just in case.
    if trace_hex.chars().all(|c| c == '0') {
        trace_hex.replace_range(0..1, "1");
    }
    let mut span = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut span);
    let span_hex: String = span.iter().map(|b| format!("{:02x}", b)).collect();
    format!("00-{}-{}-01", trace_hex, span_hex)
}
#[cfg(not(test))]
pub async fn publish(bytes: Vec<u8>, trace_id: &str) -> Result<()> {
    let addr = std::env::var("AMQP_ADDR").unwrap_or_else(|_| "amqp://rabbitmq:5672/%2f".into());

    let conn = Connection::connect(
        &addr,
        ConnectionProperties::default().with_default_executor(8),
    )
    .await?;

    info!("CONNECTED TO AQMP SERVER");

    let channel_a = conn.create_channel().await?;

    let queue = channel_a
        .queue_declare(
            "dpsim-worker-queue",
            QueueDeclareOptions::default(),
            FieldTable::default(),
        ).await?;

    info!("Declared queue {:?}", queue);

    // Stamp the trace-id into AMQP headers so the worker can correlate its
    // log lines + redis status with the originating HTTP request. P2.2.
    //
    // Alongside our short 12-hex id we also emit a W3C traceparent
    // (version=00, 32-hex trace id, 16-hex span id, flags=01 sampled). The
    // Python worker extracts it through opentelemetry's propagator so the
    // root span it creates becomes a child of this publish in the same
    // Jaeger trace — turning HTTP → AMQP → CIM build → sim.run into one
    // end-to-end waterfall instead of two disconnected trees.
    let w3c_traceparent = _build_w3c_traceparent(trace_id);
    let mut headers = FieldTable::default();
    headers.insert("x-trace-id".into(), lapin::types::AMQPValue::LongString(
        trace_id.to_string().into(),
    ));
    headers.insert("traceparent".into(), lapin::types::AMQPValue::LongString(
        w3c_traceparent.into(),
    ));
    let props = BasicProperties::default().with_headers(headers);

    let confirm = channel_a
        .basic_publish(
            "",
            "dpsim-worker-queue",
            BasicPublishOptions::default(),
            bytes,
            props,
        )
        .await?
        .await?;
    assert_eq!(confirm, Confirmation::NotRequested);
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[doc = "Struct for encapsulation Simulation details"]
pub struct AMQPSimulation {
    error: String,
    load_profile_url:  String,
    model_url:         String,
    simulation_id:     u64,
    simulation_type:   SimulationType,
    results_file:      String,
    domain:            DomainType,
    solver:            SolverType,
    timestep:          u64,
    finaltime:         u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    outage_component:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_factor:       Option<f64>
}

impl AMQPSimulation {
    pub fn from_simulation(
        sim: &Json<Simulation>,
        model_url: String,
        load_profile_url: String,
        outage_component: Option<String>,
        load_factor: Option<f64>,
    ) -> AMQPSimulation {
        AMQPSimulation {
            error:            "".into(),
            load_profile_url: load_profile_url,
            model_url:        model_url,
            simulation_id:    sim.simulation_id,
            simulation_type:  sim.simulation_type,
            results_file:     sim.results_id.clone(),
            domain:           sim.domain,
            solver:           sim.solver,
            timestep:         sim.timestep,
            finaltime:        sim.finaltime,
            outage_component: outage_component,
            load_factor:      load_factor,
        }
    }
}

pub async fn request_simulation(_simulation: &AMQPSimulation, trace_id: &str) -> Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let mut load_profile = json!("");

    if _simulation.load_profile_url != "" {
        load_profile = json!({
            "type" : "url-list",
            "url" : [ _simulation.load_profile_url ]
        });
    }

    // trace_id also goes into the body (alongside the AMQP header) so the
    // worker can surface it into redis even if the header path gets lost
    // (e.g. DLQ republish by broker).
    let message_as_jsonvalue = json!({
      "model" : {
        "type" : "url-list",
        "url" : [ _simulation.model_url ]
      },
      "load_profile" : load_profile,
      "parameters": {
        "simulation_id":   _simulation.simulation_id,
        "simulation_type": _simulation.simulation_type,
        "domain":          _simulation.domain,
        "solver":          _simulation.solver,
        "timestep":        _simulation.timestep,
        "finaltime":       _simulation.finaltime,
        "results_file":    _simulation.results_file,
        "trace_id":        trace_id,
        "outage_component": _simulation.outage_component,
        "load_factor":     _simulation.load_factor
      }
    });
    let message = serde_json::to_vec(&message_as_jsonvalue).unwrap();

    publish(message, trace_id).await?;

    Ok(())
}
