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

use super::*;

#[test]
fn reg_sigs() {
    reg_for_sigs();
}

#[test]
#[ignore]
// Must be run using cargo test -- --ignored
// This ensures only this test in run - otherwise environment variables from other
// tests run in parallel may interere
fn ssl_paths() {
    // Clear out variables
    env::remove_var(SSL_KEY_VAR);
    env::remove_var(SSL_CERT_VAR);

    // Check variables are empty
    println!(
        "SSL_KEY_VAR=\"{}\"",
        env::var(SSL_KEY_VAR).unwrap_or("".to_string())
    );
    println!(
        "SSL_CERT_VAR=\"{}\"",
        env::var(SSL_CERT_VAR).unwrap_or("".to_string())
    );
    assert!(env::var(SSL_KEY_VAR).is_err());
    assert!(env::var(SSL_CERT_VAR).is_err());

    // Get defaults
    let key = get_env_str(SSL_KEY_VAR, SSL_KEY_DEF);
    let cert = get_env_str(SSL_CERT_VAR, SSL_CERT_DEF);
    println!(
        "SSL_KEY_VAR=\"{}\", key=\"{}\", SSL_KEY_DEF=\"{}\"",
        SSL_KEY_VAR, key, SSL_KEY_DEF
    );
    println!(
        "SSL_CERT_VAR=\"{}\", cert={}, SSL_CERT_DEF=\"{}\"",
        SSL_CERT_VAR, cert, SSL_CERT_DEF
    );
    assert!(key == SSL_KEY_DEF);
    assert!(cert == SSL_CERT_DEF);

    // Set env variables and get these values
    env::set_var(SSL_KEY_VAR, "key");
    env::set_var(SSL_CERT_VAR, "cert");
    let key = get_env_str(SSL_KEY_VAR, SSL_KEY_DEF);
    let cert = get_env_str(SSL_CERT_VAR, SSL_CERT_DEF);
    println!(
        "SSL_KEY_VAR=\"{}\", key=\"{}\", SSL_KEY_DEF=\"{}\"",
        SSL_KEY_VAR, key, SSL_KEY_DEF
    );
    println!(
        "SSL_CERT_VAR=\"{}\", cert={}, SSL_CERT_DEF=\"{}\"",
        SSL_CERT_VAR, cert, SSL_CERT_DEF
    );
    assert!(key == "key");
    assert!(cert == "cert");
}

#[test]
fn env_strs() {
    env::set_var(SSL_KEY_VAR, "key");
    env::set_var(SSL_CERT_VAR, "cert");
    let env_s = get_env_strings(vec![]);
    println!("{:?}", env_s);
}

#[test]
fn ssl_test() {
    match ssl() {
        Ok(_) => (),
        Err(_) => (),
    }
}
