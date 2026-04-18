//! P2.2c — OpenTelemetry tracer for dpsim-api.
//!
//! Initializes a BatchSpanProcessor that ships to the OTLP HTTP endpoint
//! (Jaeger's :4318 by default, matching the worker). No-op when
//! `OTEL_EXPORTER_OTLP_ENDPOINT` is unset so `make up` stays portable.

use opentelemetry::{global, KeyValue};
use opentelemetry::trace::{SpanBuilder, SpanContext, SpanId, SpanKind, TraceContextExt, TraceFlags, TraceId, TraceState, Tracer};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

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

// ---------------------------------------------------------------------------
// Rocket fairing — per-request span that wraps the whole route handler.
//
// P2.2d replaces the stub `start_post_simulation_span()` (which ended
// immediately and thus reported dur=0ms in Jaeger) with a fairing that
// starts a span on on_request and ends it on on_response. The child span
// we mint inside post_simulation for AMQP publish now inherits the real
// request trace via Rocket's current-span tracking.
// ---------------------------------------------------------------------------

struct RequestSpanSlot {
    span: Option<opentelemetry::global::BoxedSpan>,
    /// Snapshot of the fairing span's context so handlers can hand it to the
    /// AMQP publisher without needing a mutable reference to the live span.
    ctx: Option<SpanContext>,
    started: Instant,
}

/// Retrieve the fairing-attached span context for a request, if any. Used by
/// post_simulation to propagate the same trace id into AMQP as the fairing
/// emits to Jaeger.
pub fn request_span_context(req: &Request<'_>) -> Option<SpanContext> {
    let slot = req.local_cache::<Mutex<RequestSpanSlot>, _>(|| {
        Mutex::new(RequestSpanSlot { span: None, ctx: None, started: Instant::now() })
    });
    slot.lock().ok().and_then(|s| s.ctx.clone())
}

/// Request guard that exposes the fairing span context to handlers. Always
/// succeeds; `.0` is `None` when OTel is off or the fairing didn't run.
pub struct RequestSpanCtx(pub Option<SpanContext>);

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for RequestSpanCtx {
    type Error = ();
    async fn from_request(
        req: &'r Request<'_>,
    ) -> rocket::request::Outcome<Self, Self::Error> {
        rocket::outcome::Outcome::Success(RequestSpanCtx(request_span_context(req)))
    }
}

impl<'r> rocket_okapi::request::OpenApiFromRequest<'r> for RequestSpanCtx {
    fn from_request_input(
        _gen: &mut rocket_okapi::gen::OpenApiGenerator,
        _name: String,
        _required: bool,
    ) -> rocket_okapi::Result<rocket_okapi::request::RequestHeaderInput> {
        Ok(rocket_okapi::request::RequestHeaderInput::None)
    }
}

pub struct TracingFairing;

#[rocket::async_trait]
impl Fairing for TracingFairing {
    fn info(&self) -> Info {
        Info {
            name: "opentelemetry-request-span",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        use opentelemetry::trace::Span as _;
        if SDK_PROVIDER.get().is_none() {
            return;
        }
        let tracer = global::tracer("dpsim-api");
        let mut span = tracer.build(
            SpanBuilder::from_name(format!("{} {}", req.method(), req.uri().path()))
                .with_kind(SpanKind::Server),
        );
        span.set_attribute(KeyValue::new("http.method", req.method().as_str().to_string()));
        span.set_attribute(KeyValue::new("http.target", req.uri().path().to_string()));
        let ctx = span.span_context().clone();
        let slot = Mutex::new(RequestSpanSlot {
            span: Some(span),
            ctx: Some(ctx),
            started: Instant::now(),
        });
        req.local_cache(|| slot);
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, resp: &mut Response<'r>) {
        use opentelemetry::trace::Span as _;
        if SDK_PROVIDER.get().is_none() {
            return;
        }
        let slot = req.local_cache::<Mutex<RequestSpanSlot>, _>(|| {
            Mutex::new(RequestSpanSlot { span: None, ctx: None, started: Instant::now() })
        });
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut span) = guard.span.take() {
            span.set_attribute(KeyValue::new("http.status_code", resp.status().code as i64));
            span.set_attribute(KeyValue::new(
                "http.duration_ms",
                guard.started.elapsed().as_millis() as i64,
            ));
            span.end();
            // NB: we don't call provider.force_flush() here. The OTLP HTTP
            // exporter blocks on the response while holding Rocket's request
            // thread, producing a hang under load. The flush happens in
            // start_post_simulation_span (which runs mid-handler on its own
            // blocking call) and on process exit. Worst case a request span
            // takes up to BatchSpanProcessor's 5s scheduled flush to appear.
        }
    }
}
