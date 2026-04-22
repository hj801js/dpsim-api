use rocket::local::blocking::Client;
use rocket::Build;
use serde::{Deserialize, Serialize};
use crate::routes::{Simulation, SimulationArray, SimulationSummary, SimulationType, DomainType, SolverType, EngineType, get_routes, incomplete_form};
use rocket::http::ContentType;
use serde_json::json;
use assert_json_diff::assert_json_eq;
use crate::Template;
use crate::routes::{SimulationForm};

#[launch]
fn rocket() -> rocket::Rocket<Build> {
    rocket::build()
        .register("/", catchers![incomplete_form])
        .mount("/", get_routes())
        .mount("/", crate::auth::get_routes())
        .attach(Template::fairing())
}

#[test]
fn test_get_simulations() {
    // Construct a client to use for dispatching requests.
    let client = Client::untracked(rocket()).expect("valid rocket instance");

    // Dispatch a request to 'GET /' and validate the response.
    let response = client.get("/simulation").dispatch();
    assert_eq!(response.status().code, 200);
    let reply = response.into_string().unwrap();
    let received_json: SimulationArray = serde_json::from_str( reply.as_str() ).unwrap();
    let received_simulation_summary = &received_json.simulations[0];
    let expected_simulation_summary = SimulationSummary {
        simulation_id:   1,
        model_id:        "1".to_string(),
        simulation_type: SimulationType::Powerflow,
        // v1.2.6 redis-fallback path populates these from the Simulation
        // stub (DomainType::SP, EngineType::Dpsim). Status stays None
        // because the test stub doesn't carry a sidechannel value.
        status:          None,
        domain:          Some(DomainType::SP),
        engine:          Some(EngineType::Dpsim),
    };
    assert_json_eq!(received_simulation_summary, expected_simulation_summary)
}

#[test]
fn test_get_simulation_by_id() {
    // Construct a client to use for dispatching requests.
    let client = Client::untracked(rocket()).expect("valid rocket instance");

    // Dispatch a request to 'GET /' and validate the response.
    let response = client.get("/simulation/1").dispatch();
    assert_eq!(response.status().code, 200);
    let reply = response.into_string().unwrap();
    let received_json: Simulation = serde_json::from_str( reply.as_str() ).unwrap();
    let expected_json = Simulation {
        error:           "".to_string(),
        load_profile_id: "".to_string(),
        model_id:        "1".to_string(),
        results_id:      "1".to_string(),
        domain:          DomainType::SP,
        solver:          SolverType::NRP,
        timestep:        1,
        finaltime:       360,
        trace_id:        "".into(),
        results_data:    r#"{
  "data": {
    "fileID": "d297cb7c-b578-4da8-9d79-76432e8986e9",
    "lastModified": "2022-04-27T09:27:09Z",
    "url": "http://minio:9000/sogno-platform/d297cb7c-b578-4da8-9d79-76432e8986e9?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ALFRED123%2F20220427%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220427T092744Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=48ec50cecae04ca34693429bc740f9a0b81e829b6e696800e823399355ab83b9"
  }
}
"#.to_string(),
        simulation_id:   1,
        simulation_type: SimulationType::Powerflow,
        engine:          EngineType::Dpsim,
    };
    assert_json_eq!(received_json, expected_json)
}

#[test]
fn test_get_openapi() {
    // Construct a client to use for dispatching requests.
    let client = Client::untracked(rocket()).expect("valid rocket instance");

    // Dispatch a request to 'GET /' and validate the response.
    let response = client.get("/openapi.json").dispatch();
    assert_eq!(response.status().code, 200);
    let reply = response.into_string().unwrap();
    let received_json: serde_json::Value = serde_json::from_str( reply.as_str() ).unwrap();
    println!("OPENAPI: {}", received_json)
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SimulationPost<> {
    simulation_type: String,
    load_profile_id: String,
    model_id:        u64
}

#[test]
fn test_post_simulation() {
    let client = Client::untracked(rocket()).expect("valid rocket instance");

    let ct = "application/json"
        .parse::<ContentType>()
        .unwrap();
   
    let form = SimulationForm {
        model_id: "1".to_string(),
        load_profile_id: "1".to_string(),
        simulation_type: SimulationType::Powerflow.into(),
        domain:          DomainType::SP,
        solver:          SolverType::NRP,
        timestep:        1,
        finaltime:       360,
        outage_component:   None,
        load_factor:        None,
        load_factor_series: None,
        engine:             EngineType::Dpsim,
    };
    let body = serde_json::to_string(&form).unwrap();
    let response = client.post("/simulation")
        .header(ct)
        .remote("127.0.0.1:8000".parse().unwrap())
        .body(&body)
        .dispatch();

    let reply = response.into_string().unwrap();
    println!("REPLY: {:?}", reply);
    let expected_simulation = json!(Simulation {
        error:             "".to_string(),
        load_profile_id:   "1".to_string(),
        model_id:          "1".to_string(),
        results_id:        "100".to_string(),
        results_data:      "".to_string(),
        simulation_id:     1,
        simulation_type:   SimulationType::Powerflow,
        domain:            DomainType::SP,
        solver:            SolverType::NRP,
        timestep:          1,
        finaltime:         360,
        trace_id:          "".into(),
        engine:            EngineType::Dpsim,
    });
    let mut received_json: Simulation = serde_json::from_str( reply.as_str() ).unwrap();
    // Trace id is randomized per request — verify it's present then neutralise
    // it so the equality check focuses on the rest of the payload.
    assert!(!received_json.trace_id.is_empty(), "trace_id should be set");
    received_json.trace_id = "".into();
    assert_json_eq!(expected_simulation, received_json)
}

#[test]
fn test_post_model_upload() {
    // P4.2 regression — POST /models with raw XML body returns the file-service
    // test stub's fixed model_id ("200" per file_service::put_model_bytes).
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let response = client
        .post("/models")
        .header(ContentType::XML)
        .body("<cim><Node id=\"n1\"/></cim>")
        .dispatch();
    assert_eq!(response.status().code, 200);
    let reply = response.into_string().unwrap();
    let body: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(body["model_id"], "200");
    assert_eq!(body["bytes"], 26);
}

#[test]
fn test_post_model_rejects_malformed_xml() {
    // C hardening — non-well-formed XML gets 400 before reaching file-service.
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let response = client
        .post("/models")
        .header(ContentType::XML)
        .body("<cim><unclosed>")
        .dispatch();
    assert_eq!(response.status().code, 400);
}

#[test]
fn test_post_model_rejects_doctype() {
    // C hardening — DOCTYPE with entity declarations is the XXE / billion-
    // laughs surface; reject unconditionally.
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let bomb = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;">
]>
<lolz>&lol2;</lolz>"#;
    let response = client
        .post("/models")
        .header(ContentType::XML)
        .body(bomb)
        .dispatch();
    assert_eq!(response.status().code, 400);
}

#[test]
fn test_post_model_accepts_zip() {
    // C hardening — ZIP bundles (PK\x03\x04) skip XML validation; the worker
    // extracts and validates them on its end.
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    // Minimal ZIP magic + random filler. The test stub returns "200"
    // regardless of contents.
    let zip_bytes: &[u8] = b"PK\x03\x04random bytes that would fail xml";
    let response = client
        .post("/models")
        .header(ContentType::new("application", "zip"))
        .body(zip_bytes)
        .dispatch();
    assert_eq!(response.status().code, 200);
}

#[test]
fn test_healthz() {
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let response = client.get("/healthz").dispatch();
    assert_eq!(response.status().code, 200);
    assert_eq!(response.into_string().unwrap(), "ok");
}

#[test]
fn test_version() {
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let response = client.get("/version").dispatch();
    assert_eq!(response.status().code, 200);
    let body: serde_json::Value =
        serde_json::from_str(&response.into_string().unwrap()).unwrap();
    assert_eq!(body["name"], "dpsim-api");
    assert!(body["version"].as_str().is_some());
    assert!(body["git_sha"].as_str().is_some());
}

#[test]
fn test_auth_signup_login_me() {
    // P4.1 regression — full signup → login → /auth/me round trip with a JWT
    // secret provided via env so issue_token succeeds. New user per test run.
    std::env::set_var("DPSIM_JWT_SECRET", "rocket-test-secret");
    let client = Client::untracked(rocket()).expect("valid rocket instance");

    let email = format!("test-{}@dpsim.local", std::process::id());
    let creds = json!({ "email": email, "password": "abcdefgh12345" });

    let signup = client.post("/auth/signup").json(&creds).dispatch();
    assert_eq!(signup.status().code, 200, "signup must 200");
    let signup_body: serde_json::Value =
        serde_json::from_str(&signup.into_string().unwrap()).unwrap();
    let token = signup_body["token"].as_str().unwrap().to_owned();

    let login = client.post("/auth/login").json(&creds).dispatch();
    assert_eq!(login.status().code, 200, "login must 200");

    let me = client
        .get("/auth/me")
        .header(rocket::http::Header::new(
            "Authorization",
            format!("Bearer {}", token),
        ))
        .dispatch();
    assert_eq!(me.status().code, 200);
    let me_body: serde_json::Value =
        serde_json::from_str(&me.into_string().unwrap()).unwrap();
    assert_eq!(me_body["email"], email);

    let me_no_token = client.get("/auth/me").dispatch();
    assert_eq!(me_no_token.status().code, 401, "no-token must 401");
}

#[test]
fn test_auth_logout_revokes_token() {
    // Session 28 — /auth/logout writes the token signature to redis with
    // TTL so subsequent requests see 401. Tests run against the stubbed
    // db module (src/main.rs #[cfg(test)] mod db) which pretends redis
    // isn't reachable — so is_token_sig_revoked returns false and we can
    // verify the route itself ran without requiring a live redis. The
    // behavioural end of the story is covered by the end-to-end cookie
    // smoke in docs/43 §6 rather than this unit test.
    std::env::set_var("DPSIM_JWT_SECRET", "rocket-test-secret");
    let client = Client::untracked(rocket()).expect("valid rocket instance");
    let email = format!("logout-{}@dpsim.local", std::process::id());
    let creds = json!({ "email": email, "password": "abcdefgh12345" });
    let signup = client.post("/auth/signup").json(&creds).dispatch();
    let token = serde_json::from_str::<serde_json::Value>(&signup.into_string().unwrap())
        .unwrap()["token"].as_str().unwrap().to_owned();

    let logout = client
        .post("/auth/logout")
        .header(rocket::http::Header::new(
            "Authorization",
            format!("Bearer {}", token),
        ))
        .dispatch();
    assert_eq!(logout.status().code, 200, "logout must 200");
    let body: serde_json::Value =
        serde_json::from_str(&logout.into_string().unwrap()).unwrap();
    assert_eq!(body["ok"], true);

    let logout_no_token = client.post("/auth/logout").dispatch();
    assert_eq!(logout_no_token.status().code, 401, "logout without bearer must 401");
}
