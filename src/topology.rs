//! `GET /topology/<model_id>` — parse CIM EQ+TP bundles server-side and
//! return a normalized JSON graph the web UI can render directly.
//!
//! Two path shapes feed this:
//!
//! 1. **Baked bundles** — `wscc9`, `ieee14`, `ieee39`, `cigre_mv`. The
//!    worker-side `CIM_BUNDLES` dict maps these to glob patterns under
//!    `$DPSIM_CIM_DATA_ROOT` (default
//!    `/Users/hk/DPsim_hk/dpsim/build/_deps/cim-data-src` for local dev;
//!    override to the path mounted into the api container).
//!
//! 2. **Uploaded model_ids** — future Phase E; if the id isn't a baked
//!    bundle, return 404 today. Upload-topology plumbing will add a
//!    branch that fetches via file-service and caches next to the
//!    worker's `/tmp/dpsim_models/<id>/` dir.

use rocket::serde::Serialize;
use rocket::serde::json::Json;
use rocket::http::Status;
use schemars::JsonSchema;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------
#[derive(Serialize, JsonSchema)]
pub struct TopologyBranch {
    pub name: String,
    pub bus_from: String,
    pub bus_to: String,
    /// "line" | "transformer" | "switch".
    pub kind: String,
}

#[derive(Serialize, JsonSchema)]
pub struct TopologyResponse {
    pub model_id: String,
    pub buses: Vec<String>,
    pub branches: Vec<TopologyBranch>,
}

#[derive(Serialize, JsonSchema)]
pub struct TopologyError {
    pub err: String,
}

// ---------------------------------------------------------------------------
// Bundle registry — mirrors dpsim/examples/service-stack/worker.py
// ---------------------------------------------------------------------------
fn cim_data_root() -> PathBuf {
    std::env::var("DPSIM_CIM_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/Users/hk/DPsim_hk/dpsim/build/_deps/cim-data-src"))
}

fn bundle_glob(model_id: &str) -> Option<PathBuf> {
    let root = cim_data_root();
    match model_id {
        "wscc9"    => Some(root.join("WSCC-09").join("WSCC-09")),
        "ieee14"   => Some(root.join("IEEE-14")),
        "ieee39"   => Some(root.join("IEEE-39")),
        "cigre_mv" => Some(
            root.join("CIGRE_MV")
                .join("NEPLAN")
                .join("CIGRE_MV_no_tapchanger_noLoad1_LeftFeeder_With_LoadFlow_Results")
        ),
        // Matpower single-file cases live in the Matpower_cases dir; the
        // generic `collect_xmls` would slurp all 5 cases if we returned
        // the dir root, so this branch uses `single_file` instead.
        _ => matpower_single(&root, model_id),
    }
}

fn matpower_single(root: &Path, model_id: &str) -> Option<PathBuf> {
    let file = match model_id {
        "matpower_case9"   => "case9.xml",
        "matpower_case14"  => "case14.xml",
        "matpower_case300" => "case300.xml",
        _ => return None,
    };
    let path = root.join("Matpower_cases").join(file);
    if path.exists() { Some(path) } else { None }
}

fn collect_xmls(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return vec![]; };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "xml").unwrap_or(false))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// CIM parsing — identical data model to ops/gen-model-catalog.py. Keep the
// two in sync: the Python generator produces the offline TS catalog, this
// endpoint produces the runtime JSON for user uploads / topology fetch.
// ---------------------------------------------------------------------------
fn parse_cim_bundle(paths: &[PathBuf]) -> Result<TopologyResponse, String> {
    let mut texts: Vec<String> = Vec::new();
    for path in paths {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let s = std::str::from_utf8(&bytes).map_err(|e| format!("utf8: {}", e))?;
        texts.push(s.to_owned());
    }
    let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    parse_cim_events(&refs)
}

fn parse_cim_events(xmls: &[&str]) -> Result<TopologyResponse, String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    // element_id → (kind, name) for ACLineSegment / PowerTransformer / switches.
    let mut elements: HashMap<String, (String, String)> = HashMap::new();
    // term_id → conducting_equipment_id (from EQ).
    let mut term_ce: HashMap<String, String> = HashMap::new();
    // term_id → node_id (from TP's TopologicalNode ref, or EQ's ConnectivityNode ref).
    let mut term_node: HashMap<String, String> = HashMap::new();
    // node_id → display name (TopologicalNode or ConnectivityNode).
    let mut node_name: HashMap<String, String> = HashMap::new();

    for (idx, text) in xmls.iter().enumerate() {
        let mut r = Reader::from_str(text);
        r.config_mut().trim_text(true);

        // We track the current open element's tag + id and its children.
        let mut stack: Vec<(String, String)> = Vec::new(); // (local_tag, id)
        // For Terminal-level parsing we need to capture which of its
        // children we are inside — track with a second small stack.
        loop {
            let ev = r.read_event().map_err(|e| format!("xml src#{}: {}", idx, e))?;
            match ev {
                Event::Start(e) => {
                    let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                    let mut rid = String::new();
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).into_owned();
                        if key == "ID" || key == "about" {
                            let v = attr.unescape_value().unwrap_or_default().to_string();
                            rid = v.trim_start_matches('#').to_owned();
                            break;
                        }
                    }
                    // Handle refs: IdentifiedObject.name text is read from
                    // the immediate Text event; for attribute-only children
                    // (e.g. <cim:Terminal.ConductingEquipment rdf:resource="#X"/>)
                    // we pull rdf:resource here.
                    if let Some((parent_tag, parent_id)) = stack.last() {
                        if parent_tag == "Terminal" {
                            // Pull rdf:resource attr out of the child element.
                            let mut resource: Option<String> = None;
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).into_owned();
                                if key == "resource" {
                                    resource = Some(
                                        attr.unescape_value().unwrap_or_default()
                                            .trim_start_matches('#').to_owned(),
                                    );
                                }
                            }
                            if let Some(res) = resource {
                                if tag == "Terminal.ConductingEquipment" {
                                    term_ce.insert(parent_id.clone(), res);
                                } else if tag == "Terminal.TopologicalNode"
                                       || tag == "Terminal.ConnectivityNode" {
                                    term_node.insert(parent_id.clone(), res);
                                }
                            }
                        }
                    }
                    stack.push((tag, rid));
                }
                Event::Empty(e) => {
                    // Self-closing child element — same parent logic as Start
                    // but no pop needed.
                    let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                    if let Some((parent_tag, parent_id)) = stack.last() {
                        let mut resource: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.local_name().as_ref()).into_owned();
                            if key == "resource" {
                                resource = Some(
                                    attr.unescape_value().unwrap_or_default()
                                        .trim_start_matches('#').to_owned(),
                                );
                            }
                        }
                        if parent_tag == "Terminal" {
                            if let Some(res) = resource.clone() {
                                if tag == "Terminal.ConductingEquipment" {
                                    term_ce.insert(parent_id.clone(), res);
                                } else if tag == "Terminal.TopologicalNode"
                                       || tag == "Terminal.ConnectivityNode" {
                                    term_node.insert(parent_id.clone(), res);
                                }
                            }
                        }
                        // Matpower-style reverse link: TopologicalNode.Terminal
                        // rdf:resource="#<term-id>" — the node owns the list.
                        if (parent_tag == "TopologicalNode" || parent_tag == "ConnectivityNode")
                            && (tag == "TopologicalNode.Terminal"
                                || tag == "ConnectivityNode.Terminal")
                        {
                            if let Some(tid) = resource {
                                term_node.entry(tid).or_insert_with(|| parent_id.clone());
                            }
                        }
                    }
                }
                Event::Text(t) => {
                    if stack.len() >= 2 {
                        let (tag, _) = &stack[stack.len() - 1];
                        if tag == "IdentifiedObject.name" {
                            let (parent_tag, parent_id) = &stack[stack.len() - 2];
                            let txt = t.unescape().unwrap_or_default().trim().to_owned();
                            if txt.is_empty() { continue; }
                            match parent_tag.as_str() {
                                "ACLineSegment" => {
                                    elements.insert(parent_id.clone(), ("line".into(), txt));
                                }
                                "PowerTransformer" => {
                                    elements.insert(parent_id.clone(), ("transformer".into(), txt));
                                }
                                "Breaker" | "Disconnector" | "LoadBreakSwitch" | "Switch" => {
                                    elements.insert(parent_id.clone(), ("switch".into(), txt));
                                }
                                "TopologicalNode" | "ConnectivityNode" => {
                                    node_name.entry(parent_id.clone()).or_insert(txt);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Event::End(_) => {
                    stack.pop();
                }
                Event::Eof => break,
                _ => {}
            }
        }
    }

    // Resolve branches.
    let mut branches: Vec<TopologyBranch> = Vec::new();
    for (eid, (kind, name)) in &elements {
        let mut buses: Vec<String> = Vec::new();
        for (tid, ce) in &term_ce {
            if ce != eid { continue; }
            if let Some(nid) = term_node.get(tid) {
                if let Some(nm) = node_name.get(nid) {
                    if !buses.contains(nm) { buses.push(nm.clone()); }
                }
            }
        }
        if buses.len() >= 2 {
            branches.push(TopologyBranch {
                name:     name.clone(),
                bus_from: buses[0].clone(),
                bus_to:   buses[1].clone(),
                kind:     kind.clone(),
            });
        }
    }
    // Stable ordering: kind then name.
    let kind_rank = |k: &str| match k { "line" => 0, "transformer" => 1, "switch" => 2, _ => 9 };
    branches.sort_by(|a, b|
        kind_rank(&a.kind).cmp(&kind_rank(&b.kind))
            .then(a.name.cmp(&b.name))
    );

    let mut buses: Vec<String> = branches.iter()
        .flat_map(|b| [b.bus_from.clone(), b.bus_to.clone()])
        .collect();
    buses.sort();
    buses.dedup();

    Ok(TopologyResponse {
        model_id: String::new(),
        buses,
        branches,
    })
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------
/// Accept only characters we know appear in real model ids — baked bundle
/// names (`wscc9`, `ieee14`, `ieee39`, `cigre_mv`, `matpower_case300`) and
/// the hex ids file-service assigns to uploads. Everything else — slashes,
/// dots, percent-encoded traversal — gets rejected before any filesystem
/// or file-service call. Rocket already url-decodes the path segment so
/// this runs on the decoded string.
fn is_safe_model_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[get("/topology/<model_id>")]
pub async fn get_topology(
    user: crate::auth::MaybeAuthedUser,
    model_id: String,
) -> Result<Json<TopologyResponse>, Status> {
    if !is_safe_model_id(&model_id) {
        return Err(Status::BadRequest);
    }
    // Guard behind auth when DPSIM_AUTH_REQUIRED is on — uploaded models
    // carry private CIM data and shouldn't be readable by anonymous probes.
    // Baked bundles could be public but we gate everything for simplicity;
    // the dev mode (flag off) stays wide open.
    if crate::auth::auth_required() && user.0.is_none() {
        return Err(Status::Unauthorized);
    }
    // Baked bundle path — worker.CIM_BUNDLES mirror.
    if let Some(path) = bundle_glob(&model_id) {
        // Handle both dir-of-xmls and single-file forms.
        let xmls: Vec<PathBuf> = if path.is_file() {
            vec![path]
        } else {
            collect_xmls(&path)
        };
        if !xmls.is_empty() {
            let mut resp = parse_cim_bundle(&xmls).map_err(|e| {
                eprintln!("[topology] parse {}: {}", model_id, e);
                Status::InternalServerError
            })?;
            resp.model_id = model_id;
            return Ok(Json(resp));
        }
    }

    // Uploaded model path — fetch from file-service, parse in-memory.
    // The file-service returns ZIP bundles or single XML; we handle both
    // without writing to disk so we don't collide with the worker cache.
    match fetch_uploaded(&model_id).await {
        Ok(Some(xmls_text)) => {
            let mut resp = parse_cim_bundle_from_strs(&xmls_text).map_err(|e| {
                eprintln!("[topology] parse uploaded {}: {}", model_id, e);
                Status::InternalServerError
            })?;
            resp.model_id = model_id;
            Ok(Json(resp))
        }
        Ok(None) => Err(Status::NotFound),
        Err(e) => {
            eprintln!("[topology] fetch {}: {}", model_id, e);
            Err(Status::BadGateway)
        }
    }
}

/// Fetch an uploaded model's XML content(s) via file-service. Returns
/// Ok(Some(xmls)) with one string per XML file (after ZIP extraction if
/// needed), Ok(None) when the id isn't in file-service.
async fn fetch_uploaded(model_id: &str) -> Result<Option<Vec<String>>, String> {
    let url = match crate::file_service::convert_id_to_url(model_id).await {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };
    let bytes = crate::file_service::get_data_from_url(&url).await
        .map_err(|e| format!("file-service fetch: {}", e))?;
    let bytes: &[u8] = &bytes;

    // Sniff ZIP magic — same as dpsim-api's POST /models guard.
    if bytes.len() >= 4 && bytes[..4] == [0x50, 0x4b, 0x03, 0x04] {
        use std::io::Read;
        let cursor = std::io::Cursor::new(bytes.to_vec());
        let mut z = zip::ZipArchive::new(cursor).map_err(|e| format!("zip open: {}", e))?;
        let mut out: Vec<String> = Vec::new();
        for i in 0..z.len() {
            let mut entry = z.by_index(i).map_err(|e| format!("zip entry {}: {}", i, e))?;
            if !entry.name().ends_with(".xml") { continue; }
            // Zip-slip guard — names embedded in the archive mustn't escape.
            let name = entry.mangled_name();
            if name.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                continue;
            }
            let mut buf = String::new();
            entry.read_to_string(&mut buf).map_err(|e| format!("zip read {}: {}", i, e))?;
            out.push(buf);
        }
        Ok(Some(out))
    } else {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| format!("utf8: {}", e))?;
        Ok(Some(vec![text.to_owned()]))
    }
}

/// parse_cim_bundle variant that takes in-memory XML strings instead of
/// file paths. Reuses the same event loop — factored below.
fn parse_cim_bundle_from_strs(xmls: &[String]) -> Result<TopologyResponse, String> {
    let as_refs: Vec<&str> = xmls.iter().map(|s| s.as_str()).collect();
    parse_cim_events(&as_refs)
}

pub fn get_routes() -> Vec<rocket::Route> {
    routes![get_topology]
}
