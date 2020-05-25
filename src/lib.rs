//
//  httpd-util - A set of utilities for building HTTP microservices
//  Copyright (C) 2019  packom.net
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

extern crate pnet;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate signal_hook;
#[macro_use]
extern crate clap;

#[cfg(test)]
mod tests;

use clap::App;
use openssl::error::ErrorStack;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use signal_hook::{register, SIGINT, SIGTERM};

const AFTER_HELP: &str = "Configured using environment variables:
    [SERVER_IP] - Local IP address or domain name to bind to
    [SERVER_PORT] - Local port to bind to
    [HTTPS] - HTTPS should be used (instead of HTTP) for this microservice
    [RUST_LOG] - Logging level, one of error, warn, info, debug, trace";

pub fn init_app(name: &str, author: &str, about: &str, args: Vec<&str>, envs: Vec<&'static str>) {
    env_logger::init();

    let version = format!("{}, {}", crate_version!(), openssl::version::version());
    info!("Version {}", version);

    let mut after_help = AFTER_HELP.to_string();
    for arg in args {
        after_help += &format!("\n    {}", arg);
    }

    let _matches = App::new(name)
        .author(author)
        .version(version.as_str())
        .about(about)
        .after_help(after_help.as_str())
        .get_matches();

    log_env(envs);

    reg_for_sigs();
}

const SSL_KEY_VAR: &str = "SSL_KEY";
const SSL_KEY_DEF: &str = "/ssl/key.pem";
const SSL_CERT_VAR: &str = "SSL_CERT";
const SSL_CERT_DEF: &str = "/ssl/cert.pem";
const SERVER_IP_VAR: &str = "SERVER_IP";
const SERVER_IP_DEF: &str = "0.0.0.0";
const SERVER_PORT_VAR: &str = "SERVER_PORT";
const SERVER_PORT_DEF: &str = "8080";
const HTTPS: &str = "HTTPS";
const RUST_LOG: &str = "RUST_LOG";
const NOT_PRESENT: &str = "<not present>";

pub fn ssl() -> Result<SslAcceptorBuilder, ErrorStack> {
    // Builds an SSL implementation for Simple HTTPS from some hard-coded file names
    let mut ssl = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    // Server authentication
    let key = get_env_str(SSL_KEY_VAR, SSL_KEY_DEF);
    let cert = get_env_str(SSL_CERT_VAR, SSL_CERT_DEF);
    debug!("Loading SSL key from {}", key);
    ssl.set_private_key_file(key, openssl::ssl::SslFiletype::PEM)?;
    debug!("Loading SSL cert from {}", cert);
    ssl.set_certificate_chain_file(cert)?;
    ssl.check_private_key()?;

    Ok(ssl)
}

fn get_env_str(var: &str, default: &str) -> String {
    match env::var(var) {
        Ok(rsp) => rsp,
        Err(_) => String::from(default),
    }
}

pub fn log_env(envs: Vec<&str>) {
    info!("Environment configuration:");
    for env in get_env_strings(envs) {
        info!("{}", env);
    }
}

pub fn get_env_strings(envs: Vec<&str>) -> Vec<String> {
    let mut envs_i = vec![SSL_KEY_VAR, SSL_CERT_VAR, SERVER_IP_VAR, SERVER_PORT_VAR, HTTPS, RUST_LOG];
    for env in envs {
        envs_i.push(env)
    }
    envs_i
        .iter()
        .map(|val| {
            format!(
                "{}: {}",
                val,
                get_env_str(val, NOT_PRESENT)
            )
        })
        .collect::<Vec<String>>()
}

pub fn https() -> bool {
    match env::var(HTTPS) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn get_addr(ip_var: &str, ip_default: &str, port_var: &str, port_default: &str) -> SocketAddr {
    let addr = [get_ip(ip_var, ip_default), get_port(port_var, port_default)].join(":");
    match addr.to_socket_addrs() {
        Ok(a) => a.as_slice()[0],
        Err(e) => panic!("Failed to get address: {}", e),
    }
}

pub fn get_server_addr() -> SocketAddr {
    get_addr(
        SERVER_IP_VAR,
        SERVER_IP_DEF,
        SERVER_PORT_VAR,
        SERVER_PORT_DEF,
    )
}

fn get_ip(ip_var: &str, ip_default: &str) -> String {
    match env::var(ip_var) {
        Ok(ip) => {
            // Test this IP is of the correct format
            match [&ip, SERVER_PORT_DEF].join(":").to_socket_addrs() {
                Ok(_) => ip,
                Err(_) => get_fallback_ip(ip_default),
            }
        }
        Err(_) => get_fallback_ip(ip_default),
    }
}

// Returns the IPv4 address of the first non-loopback interface, or passed in
// default as last resort.
fn get_fallback_ip(ip_default: &str) -> String {
    let mut ip = String::from(ip_default);
    for int in pnet::datalink::interfaces() {
        if !int.name.starts_with("lo") {
            for ipn in int.ips {
                if ipn.is_ipv4() {
                    ip = ipn.ip().to_string();
                    break;
                }
            }
        }
    }
    debug!("Using fallback IP address {}", ip);
    ip
}

fn get_port(port_var: &str, port_default: &str) -> String {
    match env::var(port_var) {
        Ok(port) => {
            // Test this port is of the correct format
            match [SERVER_IP_DEF, &port].join(":").parse::<SocketAddr>() {
                Ok(_) => port,
                Err(_) => String::from(port_default),
            }
        }
        Err(_) => String::from(port_default),
    }
}

macro_rules! reg_sig {
    ($sig: expr, $fn: tt) => {
        unsafe { register($sig, || $fn()) }
            .and_then(|_| {
                debug!("Registered for {}", stringify!($sig));
                Ok(())
            })
            .or_else(|e| {
                warn!("Failed to register for {} {:?}", stringify!($sig), e);
                Err(e)
            })
            .ok();
    }
}

macro_rules! handle_sig {
    ($sig: expr, $st: tt) => {
        warn!("{} caught - exiting", stringify!($sig));
        std::process::exit(128 + $sig);
    }
}

pub fn reg_for_sigs() {
    reg_sig!(SIGINT, on_sigint);
    reg_sig!(SIGTERM, on_sigterm);
}

fn on_sigint() {
    handle_sig!(SIGINT, "SIGINT");
}

fn on_sigterm() {
    handle_sig!(SIGTERM, "SIGTERM");
}

