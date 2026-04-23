
extern crate hyper_multipart_rfc7578 as hyper_multipart;

#[cfg(not(test))]
use hyper::{body::HttpBody as _, Client, Request};
use bytes::{BytesMut,Bytes};
#[cfg(not(test))]
use hyper_multipart::client::{multipart};
#[cfg(not(test))]
use std::io::Cursor;
#[cfg(test)]
use std::{fs::File,io::Read};

/// Shared error type across this module. Callers get a single shape to
/// pattern-match on; internal failures (bad URI parse, malformed response
/// body, upstream hiccup) all map to the same `FileServiceError::Upstream`
/// surface so the HTTP layer can always produce a clean 502.
pub type FileServiceError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(not(test))]
fn file_service_base() -> String {
    std::env::var("FILE_SERVICE_URL")
        .unwrap_or_else(|_| "http://sogno-file-service:8080".into())
}

#[cfg(not(test))]
pub async fn post_results_file() -> Result<Box<Bytes>, FileServiceError> {
    let client = Client::new();
    let mut form = multipart::Form::default();
    let bytes = Cursor::new("{\"ready\":\"false\"}");
    form.add_reader_file("file", bytes, "ready.json");
    let url = format!("{}/api/files", file_service_base());
    let req_builder = Request::post(url);
    // set_body_convert can fail on malformed headers; propagate instead of
    // panicking so a misconfigured file-service base doesn't crash the
    // Rocket worker thread.
    let req = form.set_body_convert::<hyper::Body, multipart::Body>(req_builder)?;
    let mut resp = client.request(req).await?;
    let body = resp.body_mut();
    let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk?);
    }
    let frozen = buf.freeze();
    Ok(Box::new(frozen))
}

#[cfg(not(test))]
pub async fn create_results_file() -> Result<String, FileServiceError> {
    let boxed_data = post_results_file().await?;
    // file-service response is UTF-8 JSON `{"data":{"fileID":"..."}}`
    // on success or `{"error":{"message":"..."}}` on failure. Both paths
    // used to unwrap — now they surface as FileServiceError so the caller
    // returns a 502 instead of a panic.
    let body = std::str::from_utf8(&boxed_data)
        .map_err(|e| -> FileServiceError { format!("file-service body not utf-8: {}", e).into() })?;
    let body_json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| -> FileServiceError { format!("file-service body not json: {}", e).into() })?;
    if body_json.get("data").is_some() {
        match body_json["data"]["fileID"].as_str() {
            Some(id) => Ok(id.to_string()),
            None => Err("file-service response missing data.fileID".into()),
        }
    } else {
        let msg = body_json["error"]["message"]
            .as_str()
            .unwrap_or("file-service reported an error with no message");
        Err(msg.to_string().into())
    }
}

#[cfg(test)]
pub async fn create_results_file() -> Result<String, FileServiceError> {
    let file_id: String = "100".to_string();
    Ok(file_id)
}

#[cfg(test)]
pub async fn get_data_from_url(url: &str) -> Result<Box<Bytes>, FileServiceError> {
    println!("get_data_from_url{:?}", url);
    let mut f = File::open("testdata/file_service_test.json")?;
    let mut buf = BytesMut::with_capacity(1024*10);
    buf.resize(2014 * 10, 0);
    let count = f.read(&mut buf[..])?;
    println!("read {:?}", count);
    buf.truncate(count);
    let frozen = buf.freeze();
    Ok(Box::new(frozen))
}

#[cfg(not(test))]
pub async fn get_data_from_url(url: &str) -> Result<Box<Bytes>, FileServiceError> {
    let client = Client::new();
    // Parse can fail when the url carries unexpected characters — usually
    // because some upstream propagated an error message back into a URL
    // field. Surface as a FileServiceError so the handler returns a 502
    // instead of panicking the Rocket worker thread.
    let uri = url
        .parse::<hyper::Uri>()
        .map_err(|e| -> FileServiceError {
            format!("invalid file-service URI {url:?}: {e}").into()
        })?;

    // Await the response...
    let mut resp = client.get(uri).await?;
    let body = resp.body_mut();
    let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk?);
    }
    let frozen = buf.freeze();
    Ok(Box::new(frozen))
}

/// Test stub — returns a fixed model_id so unit tests don't need a live
/// file-service. Mirrors the behaviour of `create_results_file`.
#[cfg(test)]
pub async fn put_model_bytes(_bytes: Vec<u8>, _content_type: &str)
    -> Result<String, Box<dyn std::error::Error + Send + Sync>>
{
    Ok("200".to_string())
}

/// POST /api/files to allocate a new fileID, then PUT the raw bytes to
/// /api/files/<fid>. Returns the fileID (= model_id on the submit form).
#[cfg(not(test))]
pub async fn put_model_bytes(bytes: Vec<u8>, content_type: &str)
    -> Result<String, FileServiceError>
{
    // Step 1 — create a new file slot (reuses the existing multipart helper).
    let file_id = create_results_file().await?;
    // Step 2 — upload the bytes to that slot.
    let client = Client::new();
    let url = format!("{}/api/files/{}", file_service_base(), file_id);
    let req = Request::put(&url)
        .header("Content-Type", content_type)
        .body(hyper::Body::from(bytes))?;
    let resp = client.request(req).await?;
    if !resp.status().is_success() {
        return Err(format!("file-service PUT {} -> {}", url, resp.status()).into());
    }
    Ok(file_id)
}

#[doc = "Function to get a URL from sogno-file-service using a file ID. \
         Errors bubble up as FileServiceError so callers can emit a proper \
         502 instead of panicking (was the source of the session 33 \
         get_simulation_id panic on seeded test data)."]
pub async fn convert_id_to_url(model_id: &str) -> Result<String, FileServiceError> {
    #[cfg(not(test))]
    let base = file_service_base();
    #[cfg(test)]
    let base = String::from("http://sogno-file-service:8080");
    let model_id_url = format!("{}/api/files/{}", base, model_id);
    let boxed_data = get_data_from_url(&model_id_url).await?;
    let body = std::str::from_utf8(&boxed_data)
        .map_err(|e| -> FileServiceError { format!("file-service body not utf-8: {}", e).into() })?;
    let body_json: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| -> FileServiceError { format!("file-service body not json: {}", e).into() })?;
    if body_json.get("data").is_some() {
        match body_json["data"]["url"].as_str() {
            Some(url) => Ok(url.to_string()),
            None => Err("file-service response missing data.url".into()),
        }
    } else {
        let msg = body_json["error"]["message"]
            .as_str()
            .unwrap_or("file-service reported an error with no message");
        Err(msg.to_string().into())
    }
}


