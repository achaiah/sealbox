use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};

use crate::{
    api::state::AppState,
    error::{Result, SealboxError},
};

pub(crate) async fn static_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            if constant_time_eq(token.as_bytes(), state.config.auth_token.as_bytes()) {
                Ok(next.run(request).await)
            } else {
                Err(SealboxError::Unauthorized)
            }
        }
        _ => Err(SealboxError::Unauthorized),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"same-token", b"same-token"));
        assert!(!constant_time_eq(b"same-token", b"other-token"));
        assert!(!constant_time_eq(b"short", b"shorter"));
    }
}
