/// Copyright 2020 Developers of the http-tunnel project.
///
/// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
/// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
/// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
/// option. This file may not be copied, modified, or distributed
/// except according to those terms.

#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate serde_derive;

use log::{error, info};
use rand::{thread_rng, Rng};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_native_tls::TlsAcceptor;

use crate::configuration::{ProxyConfiguration, ProxyMode};
use crate::http_tunnel_codec::{HttpTunnelCodec, HttpTunnelCodecBuilder, HttpTunnelTarget};
use crate::proxy_target::{SimpleCachingDnsResolver, SimpleTcpConnector, TargetConnector};
use crate::tunnel::{
    relay_connections, ConnectionTunnel, TunnelCtx, TunnelCtxBuilder, TunnelStats,
};
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncWrite};

pub use native_tls;
pub use regex;

pub mod configuration;
pub mod http_tunnel_codec;
pub mod proxy_target;
pub mod relay;
pub mod tunnel;
pub mod auth;

type DnsResolver = SimpleCachingDnsResolver;

pub struct HttpTunnel {
    config: ProxyConfiguration,
    dns_resolver: SimpleCachingDnsResolver
}

impl HttpTunnel {
    pub fn new(config: ProxyConfiguration) -> Self {
        let dns_resolver = DnsResolver::new(
            config
            .tunnel_config
            .target_connection
            .dns_cache_ttl,
            config
            .tunnel_config
            .target_connection
            .ipv4_only
        );
        Self { config, dns_resolver }
    }

    pub async fn run(&self) -> io::Result<()> {
        info!("Starting listener on: {}", self.config.bind_address);

        let mut tcp_listener = TcpListener::bind(&self.config.bind_address)
            .await
            .map_err(|e| {
                error!(
                    "Error binding address {}: {}",
                    &self.config.bind_address, e
                );
                e
            })?;
        match &self.config.mode {
            ProxyMode::Http => {
                self.serve_http(tcp_listener).await?;
            },
            ProxyMode::Https(tls_identity) => {
                self.serve_https(tls_identity.clone(), tcp_listener).await?;
            },
            ProxyMode::Tcp(destination) => {
                let destination = destination.clone();
                serve_tcp(
                    self.config.clone(),
                    &mut tcp_listener,
                    self.dns_resolver.clone(),
                    destination,
                )
                    .await?;
            },
        }

        info!("Proxy stopped");
        Ok(())
    }

    async fn serve_http(&self, mut tcp_listener: TcpListener) -> io::Result<()> {
        serve_plain_text(
            self.config.clone(),
            &mut tcp_listener,
            self.dns_resolver.clone()
        ).await?;
        Ok(())
    }

    async fn serve_https(
            &self,
            tls_identity: native_tls::Identity,
            mut tcp_listener: TcpListener
    ) -> io::Result<()> {
        let acceptor = native_tls::TlsAcceptor::new(tls_identity.clone()).map_err(|e| {
            error!("Error setting up TLS {}", e);
            Error::from(ErrorKind::InvalidInput)
        })?;

        let tls_acceptor = TlsAcceptor::from(acceptor);

        serve_tls(
            self.config.clone(),
            &mut tcp_listener,
            tls_acceptor,
            self.dns_resolver.clone(),
        )
            .await?;
        Ok(())
    }
}

async fn serve_tls(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    tls_acceptor: TlsAcceptor,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let stream_tls_acceptor = tls_acceptor.clone();
                let config = config.clone();
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    handle_client_tls_connection(
                        config,
                        stream_tls_acceptor,
                        stream,
                        dns_resolver_ref,
                    )
                    .await
                });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn serve_plain_text(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();

        match socket {
            Ok((stream, _)) => {
                stream.nodelay().unwrap_or_default();
                let config = config.clone();
                // handle accepted connections asynchronously
                tokio::spawn(async move { tunnel_stream(&config, stream, dns_resolver_ref).await });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn serve_tcp(
    config: ProxyConfiguration,
    listener: &mut TcpListener,
    dns_resolver: DnsResolver,
    destination: String,
) -> io::Result<()> {
    info!("Serving requests on: {}", config.bind_address);
    loop {
        // Asynchronously wait for an inbound socket.
        let socket = listener.accept().await;

        let dns_resolver_ref = dns_resolver.clone();
        let destination_copy = destination.clone();
        let config_copy = config.clone();

        match socket {
            Ok((stream, _)) => {
                let config = config.clone();
                stream.nodelay().unwrap_or_default();
                // handle accepted connections asynchronously
                tokio::spawn(async move {
                    let ctx = TunnelCtxBuilder::default()
                        .id(thread_rng().gen::<u128>())
                        .build()
                        .expect("TunnelCtxBuilder failed");

                    let mut connector: SimpleTcpConnector<HttpTunnelTarget, DnsResolver> =
                        SimpleTcpConnector::new(
                            dns_resolver_ref,
                            config.tunnel_config.target_connection.connect_timeout,
                            ctx,
                        );

                    match connector
                        .connect(&HttpTunnelTarget {
                            target: destination_copy,
                            nugget: None,
                        })
                        .await
                    {
                        Ok(destination) => {
                            let stats = relay_connections(
                                stream,
                                destination,
                                ctx,
                                config_copy.tunnel_config.client_connection.relay_policy,
                                config_copy.tunnel_config.target_connection.relay_policy,
                            )
                            .await;

                            report_tunnel_metrics(ctx, stats);
                        }
                        Err(e) => error!("Failed to establish TCP upstream connection {:?}", e),
                    }
                });
            }
            Err(e) => error!("Failed TCP handshake {}", e),
        }
    }
}

async fn handle_client_tls_connection(
    config: ProxyConfiguration,
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let opt_initiation_timeout = config.tunnel_config.client_connection.initiation_timeout;
    let timed_tls_handshake = if let Some(initiation_timeout) = opt_initiation_timeout {
        timeout(initiation_timeout, tls_acceptor.accept(stream)).await
    } else {
        Ok(tls_acceptor.accept(stream).await)
    };

    if let Ok(tls_result) = timed_tls_handshake {
        match tls_result {
            Ok(downstream) => {
                tunnel_stream(&config, downstream, dns_resolver).await?;
            }
            Err(e) => {
                error!(
                    "Client opened a TCP connection but TLS handshake failed: {}.",
                    e
                );
            }
        }
    } else {
        error!(
            "Client opened TCP connection but didn't complete TLS handshake in time: {:?}.",
            config.tunnel_config.client_connection.initiation_timeout
        );
    }
    Ok(())
}

/// Tunnel via a client connection.
/// This method constructs `HttpTunnelCodec` and `SimpleTcpConnector`
/// to create an `HTTP` tunnel.
async fn tunnel_stream<C: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    config: &ProxyConfiguration,
    client: C,
    dns_resolver: DnsResolver,
) -> io::Result<()> {
    let ctx = TunnelCtxBuilder::default()
        .id(thread_rng().gen::<u128>())
        .build()
        .expect("TunnelCtxBuilder failed");

    // here it can be any codec.
    let codec: HttpTunnelCodec = HttpTunnelCodecBuilder::default()
        .tunnel_ctx(ctx)
        .enabled_targets(
            config
                .tunnel_config
                .target_connection
                .allowed_targets
                .clone(),
        )
        .auth(config.auth.clone())
        .build()
        .expect("HttpTunnelCodecBuilder failed");

    // any `TargetConnector` would do.
    let connector: SimpleTcpConnector<HttpTunnelTarget, DnsResolver> = SimpleTcpConnector::new(
        dns_resolver,
        config.tunnel_config.target_connection.connect_timeout,
        ctx,
    );

    let stats = ConnectionTunnel::new(codec, connector, client, config.tunnel_config.clone(), ctx)
        .start()
        .await;

    report_tunnel_metrics(ctx, stats);

    Ok(())
}

/// Placeholder for proper metrics emission.
/// Here we just write to a file without any aggregation.
fn report_tunnel_metrics(ctx: TunnelCtx, stats: io::Result<TunnelStats>) {
    match stats {
        Ok(s) => {
            info!(target: "metrics", "{}", serde_json::to_string(&s).expect("JSON serialization failed"));
        }
        Err(_) => error!("Failed to get stats for TID={}", ctx),
    }
}
