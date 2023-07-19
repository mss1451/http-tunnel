/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.
use crate::{
    relay::{RelayPolicy, NO_BANDWIDTH_LIMIT, NO_TIMEOUT},
    auth::ProxyAuthorization
};
use native_tls::Identity;
use regex::Regex;
use std::time::Duration;

#[derive(Clone)]
pub struct ClientConnectionConfig {
    pub initiation_timeout: Duration,
    pub relay_policy: RelayPolicy,
}

#[derive(Clone)]
pub struct TargetConnectionConfig {
    pub dns_cache_ttl: Duration,
    pub allowed_targets: Regex,
    pub connect_timeout: Duration,
    pub relay_policy: RelayPolicy,
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
                initiation_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
            target_connection: TargetConnectionConfig {
                dns_cache_ttl: NO_TIMEOUT,
                allowed_targets: Regex::new(".*").expect("Bug: bad default regexp"),
                connect_timeout: NO_TIMEOUT,
                relay_policy: RelayPolicy {
                    idle_timeout: NO_TIMEOUT,
                    min_rate_bpm: 0,
                    max_rate_bps: NO_BANDWIDTH_LIMIT,
                },
            },
        }
    }
}
