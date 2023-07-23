/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::{
    relay::RelayPolicy,
    auth::ProxyAuthorization
};
use native_tls::Identity;
use regex::Regex;
use std::time::Duration;

#[derive(Clone)]
pub struct ClientConnectionConfig {
    pub initiation_timeout: Option<Duration>,
    pub relay_policy: RelayPolicy,
}

#[derive(Clone)]
pub struct TargetConnectionConfig {
    pub dns_cache_ttl: Option<Duration>,
    pub allowed_targets: Regex,
    pub connect_timeout: Option<Duration>,
    pub relay_policy: RelayPolicy,
    pub ipv4_only: bool
}

#[derive(Clone)]
pub struct TunnelConfig {
    pub client_connection: ClientConnectionConfig,
    pub target_connection: TargetConnectionConfig,
}

#[derive(Clone)]
pub enum ProxyMode {
    Http,
    Https(Identity),
    Tcp(String),
}

#[derive(Clone, Builder)]
pub struct ProxyConfiguration {
    pub mode: ProxyMode,
    pub bind_address: String,
    pub auth: Option<ProxyAuthorization>,
    pub tunnel_config: TunnelConfig,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        // by default no restrictions
        Self {
            client_connection: ClientConnectionConfig {
                initiation_timeout: None,
                relay_policy: RelayPolicy {
                    idle_timeout: None,
                    min_rate_bpm: None,
                    max_rate_bps: None,
                },
            },
            target_connection: TargetConnectionConfig {
                dns_cache_ttl: None,
                allowed_targets: Regex::new(".*").expect("Bug: bad default regexp"),
                connect_timeout: None,
                relay_policy: RelayPolicy {
                    idle_timeout: None,
                    min_rate_bpm: None,
                    max_rate_bps: None,
                },
                ipv4_only: false
            },
        }
    }
}
