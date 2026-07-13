use rust_embed::RustEmbed;
use axum::{body::Body, http::{header, StatusCode, Uri}, response::Response};

#[derive(RustEmbed)]
#[folder = "frontend/dist/"]
pub(crate) struct Frontend;

pub(crate) async fn frontend_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = Frontend::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return Response::builder()
            .header(header::CONTENT_TYPE, mime.as_ref())
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    // SPA fallback: unknown path → index.html (Vue router handles it client-side).
    if let Some(file) = Frontend::get("index.html") {
        return Response::builder()
            .header(header::CONTENT_TYPE, "text/html")
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .unwrap()
}

