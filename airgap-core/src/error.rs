//! Application error envelope shared between online tool and frontend.
//!
//! Every 4xx/5xx response from the online tool serializes as
//! `{"code": "...", "message": "..."}`. The `code` is a stable string
//! discriminator the frontend dispatches on; `message` is a human-readable
//! description for display. Status code is derived from `code` in one
//! central mapping so handlers never reach for raw HTTP status numbers.

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Stable error categories. Each variant maps 1:1 to an HTTP status code
/// via [`ErrorCode::status`]. Multiple codes may share a status (e.g.
/// `InsufficientFunds` and `NoRewards` both return 409); the frontend
/// keys off `code`, not status, so the share is unambiguous.
#[derive(Serialize, Deserialize, TS, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
pub enum ErrorCode {
    /// Pool, payment address, or reward address has not been configured yet.
    NotConfigured,
    /// Online tool has not been paired with a signer.
    NotPaired,
    /// Koios (or another upstream Cardano data service) returned an error,
    /// timed out, or returned data the online tool could not parse.
    UpstreamUnavailable,
    /// A snapshot the operation needs (leaderlog stake snapshot, KES status,
    /// genesis params) is not yet available locally.
    SnapshotNotReady,
    /// Payment address has no UTXOs or cannot cover the transaction fee.
    InsufficientFunds,
    /// No rewards available to withdraw at the moment.
    NoRewards,
    /// Request payload is invalid: missing required field, malformed hex,
    /// unparseable address, corrupt UR fragments, etc. The accompanying
    /// `message` identifies which field.
    InvalidInput,
    /// Cardano node refused to accept the submitted transaction.
    SubmitRejected,
    /// Unexpected backend failure (transaction builder, encoder,
    /// disk I/O, etc.).
    Internal,
}

impl ErrorCode {
    /// HTTP status code carried in the response for this error category.
    pub fn status(self) -> http::StatusCode {
        use http::StatusCode as S;
        match self {
            Self::NotConfigured => S::PRECONDITION_FAILED,
            Self::NotPaired => S::PRECONDITION_REQUIRED,
            Self::UpstreamUnavailable => S::BAD_GATEWAY,
            Self::SnapshotNotReady => S::SERVICE_UNAVAILABLE,
            Self::InsufficientFunds => S::CONFLICT,
            Self::NoRewards => S::CONFLICT,
            Self::InvalidInput => S::BAD_REQUEST,
            Self::SubmitRejected => S::BAD_GATEWAY,
            Self::Internal => S::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Wire body for every 4xx/5xx response from the online tool.
#[derive(Serialize, Deserialize, TS, Debug, Clone)]
#[ts(export, export_to = "../frontend/src/types/core-wire.ts")]
pub struct ErrorEnvelope {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorEnvelope {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn not_configured(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotConfigured, message)
    }
    pub fn not_paired(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotPaired, message)
    }
    pub fn upstream(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::UpstreamUnavailable, message)
    }
    pub fn snapshot_not_ready(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::SnapshotNotReady, message)
    }
    pub fn insufficient_funds(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InsufficientFunds, message)
    }
    pub fn no_rewards(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NoRewards, message)
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }
    pub fn submit_rejected(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::SubmitRejected, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

impl IntoResponse for ErrorEnvelope {
    fn into_response(self) -> Response {
        (self.code.status(), Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_with_snake_case_code() {
        let env = ErrorEnvelope::not_paired("pair first");
        let json = serde_json::to_string(&env).unwrap();
        assert_eq!(json, r#"{"code":"not_paired","message":"pair first"}"#,);
    }

    #[test]
    fn round_trips_through_json() {
        let original = ErrorEnvelope::invalid("bad hex");
        let json = serde_json::to_string(&original).unwrap();
        let parsed: ErrorEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, ErrorCode::InvalidInput);
        assert_eq!(parsed.message, "bad hex");
    }

    #[test]
    fn intentional_status_shares() {
        assert_eq!(
            ErrorCode::InsufficientFunds.status(),
            http::StatusCode::CONFLICT
        );
        assert_eq!(ErrorCode::NoRewards.status(), http::StatusCode::CONFLICT);
        assert_eq!(
            ErrorCode::UpstreamUnavailable.status(),
            http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            ErrorCode::SubmitRejected.status(),
            http::StatusCode::BAD_GATEWAY
        );
    }
}
