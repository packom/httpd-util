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
fn ssl_paths() {
    let key = get_env_str(SSL_KEY_VAR, SSL_KEY_DEF);
    assert!(key == SSL_KEY_DEF);
    let cert = get_env_str(SSL_CERT_VAR, SSL_CERT_DEF);
    assert!(cert == SSL_CERT_DEF);
    env::set_var(SSL_KEY_VAR, "key");
    env::set_var(SSL_CERT_VAR, "cert");
    let key = get_env_str(SSL_KEY_VAR, SSL_KEY_DEF);
    assert!(key == "key");
    let cert = get_env_str(SSL_CERT_VAR, SSL_CERT_DEF);
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

