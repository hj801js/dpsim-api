//! P2.2c — OpenTelemetry tracer for dpsim-api.
//!
//! Initializes a BatchSpanProcessor that ships to the OTLP HTTP endpoint
//! (Jaeger's :4318 by default, matching the worker). No-op when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is unset so `make up` stays portable.

use opentelemetry::{global, KeyValue};
use opentelemetry::trace::{SpanBuilder, SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use std::sync::OnceLock;

static SDK_PROVIDER: OnceLock<sdktrace::TracerProvider> = OnceLock::new();

/// Install the OTLP exporter + SDK tracer provider. Called once at startup;
/// silently skipped when no endpoint env is configured. Returns true when
/// tracing is live.
pub fn init() -> bool {
    let endpoint = match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        Ok(v) if !v.is_empty() => v,
        _ => return false,
    };
    // OTLP HTTP convention: append /v1/traces if the caller didn't.
    let traces_url = if endpoint.ends_with("/v1/traces") {
        endpoint
    } else {
        format!("{}/v1/traces", endpoint.trim_end_matches('/'))
    };

    let pipeline = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .http()
                .with_endpoint(traces_url),
        )
        .with_trace_config(sdktrace::config().with_resource(Resource::new(vec![
            KeyValue::new("service.name", "dpsim-api"),
        ])))
        .install_batch(runtime::Tokio);

    match pipeline {
        Ok(provider) => {
            global::set_tracer_provider(provider.clone());
            let _ = SDK_PROVIDER.set(provider);
            true
        }
        Err(e) => {
            eprintln!("[otel] exporter init failed: {}", e);
            false
        }
    }
}

/// Start a root span named `post_simulation` whose W3C context will be
/// exported to Jaeger. The returned `SpanContext` is what `publish()` turns
/// into the AMQP traceparent header so downstream worker spans become
/// children. Keeping this opaque (not exposing the SDK Span directly) lets
/// us swap the implementation later without ripple through routes.rs.
pub fn start_post_simulation_span() -> Option<SpanContext> {
    use opentelemetry::trace::Span as _;
    let tracer = global::tracer("dpsim-api");
    let mut span = tracer.build(
        SpanBuilder::from_name("post_simulation").with_kind(SpanKind::Server),
    );
    let ctx = span.span_context().clone();
    span.end();
    // Rocket's tokio runtime doesn't drive the BatchSpanProcessor workers the
    // SDK spawned on `install_batch(runtime::Tokio)`, so spans linger in the
    // buffer until the process shuts down. Force a flush so Jaeger sees them
    // during the request cycle.
    if let Some(provider) = SDK_PROVIDER.get() {
        for r in provider.force_flush() {
            if let Err(e) = r {
                eprintln!("[otel] force_flush error: {:?}", e);
            }
        }
    }
    if !ctx.is_valid() {
        return None;
    }
    Some(ctx)
}

/// Format a W3C traceparent string from an OTel SpanContext. Returns None
/// when the context is invalid.
pub fn span_context_to_traceparent(ctx: &SpanContext) -> Option<String> {
    if !ctx.is_valid() {
        return None;
    }
    Some(format!(
        "00-{}-{}-{:02x}",
        hex_trace_id(ctx.trace_id()),
        hex_span_id(ctx.span_id()),
        ctx.trace_flags().to_u8(),
    ))
}

fn hex_trace_id(id: TraceId) -> String {
    // opentelemetry-rust renders TraceId with Display to 32 hex chars.
    format!("{:032x}", u128::from_be_bytes(id.to_bytes()))
}

fn hex_span_id(id: SpanId) -> String {
    format!("{:016x}", u64::from_be_bytes(id.to_bytes()))
}

// Re-export for callers that want to build their own span contexts —
// currently unused externally but cheap to expose.
#[allow(dead_code)]
pub fn make_context(trace_id: TraceId, span_id: SpanId) -> SpanContext {
    SpanContext::new(trace_id, span_id, TraceFlags::SAMPLED, true, TraceState::default())
}
