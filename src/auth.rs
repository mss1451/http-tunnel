use std::{error::Error, fmt::Display, string::FromUtf8Error};

use base64::{DecodeError, Engine};
use regex::Regex;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProxyAuthorization {
    pub username: String,
    pub password: String
}

impl ProxyAuthorization {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    /// Tries parsing Proxy-Authorization header value.
    pub fn from_proxy_auth(header_value: &str) -> Result<Self, ProxyAuthError> {
        let pattern_str = r"^(basic|Basic|BASIC) (?<base64>[A-Za-z0-9+/]+={0,2}$)";
        let pattern = Regex::new(pattern_str).expect("invalid regex");

        let b64 = pattern.captures(header_value).and_then(|captures| {
            captures.name("base64")
        })
        .ok_or(ProxyAuthError::RegexMismatch)?;

        let decoder = base64::engine::general_purpose::STANDARD;

        let decoded_bytes = decoder.decode(b64.as_str()).map_err(|err| {
            ProxyAuthError::Base64Decode { source: err }
        })?;
        let decoded_str = String::from_utf8(decoded_bytes).map_err(|err| {
            ProxyAuthError::Base64ToStr { source: err }
        })?;

        let decoded_str_clone = decoded_str.clone();
        let mut name_pw_parts = decoded_str_clone.split(':');

        let username = name_pw_parts.next().ok_or(ProxyAuthError::UsernameMissing {
            full_part: decoded_str.clone()
        })?.to_owned();

        let password = name_pw_parts.next().ok_or(ProxyAuthError::PasswordMissing {
            full_str: decoded_str
        })?.to_owned();

        Ok(Self { username, password })
    }
}

#[derive(Debug)]
pub enum ProxyAuthError {
    RegexMismatch,
    Base64Decode {
        source: DecodeError
    },
    Base64ToStr {
        source: FromUtf8Error
    },
    UsernameMissing {
        full_part: String
    },
    PasswordMissing {
        full_str: String
    }
}

impl Display for ProxyAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyAuthError::RegexMismatch => {
                write!(f, "Basic auth regex failed to match the header value")
            }
            ProxyAuthError::Base64Decode { source: _ } => {
                write!(f, "Decoding base64 part failed")
            },
            ProxyAuthError::Base64ToStr { source: _ } => {
                write!(f, "Failed to convert decoded base64 bytes to a UTF-8 string")
            },
            ProxyAuthError::UsernameMissing { full_part: _ } => {
                write!(f, "Decoded 'username:password' string is missing username")
            },
            ProxyAuthError::PasswordMissing { full_str: _ } => {
                write!(f, "Decoded 'username:password' string is missing password")
            },
        }
    }
}

impl Error for ProxyAuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProxyAuthError::RegexMismatch => None,
            ProxyAuthError::Base64Decode { source } => Some(source),
            ProxyAuthError::Base64ToStr { source } => Some(source),
            ProxyAuthError::UsernameMissing { full_part: _ } => None,
            ProxyAuthError::PasswordMissing { full_str: _ } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::ProxyAuthError;

    use super::ProxyAuthorization;

    #[test]
    fn parse_basic_auth() {
        let expected_name = "aaa_user";
        let expected_password = "bbb_password";
        let header_value = "basic YWFhX3VzZXI6YmJiX3Bhc3N3b3Jk";
        let auth = ProxyAuthorization::from_proxy_auth(header_value).unwrap();
        assert_eq!(auth.username, expected_name);
        assert_eq!(auth.password, expected_password);
    }
    
    #[test]
    fn parse_bad_basic_auth() {
        let header_value = "bazic YWFhX3VzZXI6YmJiX3Bhc3N3b3Jk";
        let result = ProxyAuthorization::from_proxy_auth(header_value);
        assert!(matches!(result, Err(ProxyAuthError::RegexMismatch)));
    }
}
