use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::state::Manager;

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<Manager>,
}

pub fn router(manager: Arc<Manager>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_js))
        .route("/api/state", get(api_state))
        .route("/api/scan", post(api_scan))
        .route("/api/health", get(api_health))
        .with_state(AppState { manager })
}

async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
}

async fn styles() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("web/styles.css"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("web/app.js"),
    )
}

async fn api_state(State(s): State<AppState>) -> Json<crate::state::AppStateJson> {
    Json(s.manager.snapshot().await)
}

async fn api_scan(State(s): State<AppState>) -> StatusCode {
    s.manager.scan_trigger.notify_waiters();
    StatusCode::ACCEPTED
}

async fn api_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}
