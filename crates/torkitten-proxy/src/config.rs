use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

use serde_json::{Map, Value, json};
use torkitten_core::{Mapping, MappingTarget, Site, SiteId, Transport};

use crate::CaddyError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaddyPaths {
    pub binary: PathBuf,
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
}

impl CaddyPaths {
    #[must_use]
    pub fn new(
        binary: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: binary.into(),
            state_directory: state_directory.into(),
            runtime_directory: runtime_directory.into(),
        }
    }

    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.state_directory.join("caddy.json")
    }

    #[must_use]
    pub fn admin_socket(&self) -> PathBuf {
        self.runtime_directory.join("admin.sock")
    }

    #[must_use]
    pub fn site_runtime_directory(&self, site_id: &SiteId) -> PathBuf {
        self.runtime_directory.join("sites").join(site_id.as_str())
    }

    #[must_use]
    pub fn site_socket(&self, site_id: &SiteId, virtual_port: u16) -> PathBuf {
        self.site_runtime_directory(site_id)
            .join(format!("caddy-{virtual_port}.sock"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySite {
    pub site: Site,
    pub onion_hostname: String,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub portal_upstream: PathBuf,
    pub authentication_upstream: PathBuf,
    pub bootstrap_upstream: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyConfig {
    pub sites: Vec<ProxySite>,
}

impl ProxyConfig {
    /// Validates all site, TLS, listener, and upstream inputs before rendering.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid site configuration, onion hostnames,
    /// duplicate site identities or hostnames, and unsafe filesystem paths.
    pub fn validate(&self) -> Result<(), CaddyError> {
        let mut site_ids = HashSet::with_capacity(self.sites.len());
        let mut hostnames = HashSet::with_capacity(self.sites.len());
        for proxy_site in &self.sites {
            proxy_site.site.validate()?;
            validate_onion_hostname(&proxy_site.onion_hostname)?;
            if !site_ids.insert(proxy_site.site.id.clone()) {
                return Err(CaddyError::DuplicateSiteId(proxy_site.site.id.clone()));
            }
            if !hostnames.insert(proxy_site.onion_hostname.clone()) {
                return Err(CaddyError::DuplicateOnionHostname(
                    proxy_site.onion_hostname.clone(),
                ));
            }
            for path in [
                &proxy_site.certificate_path,
                &proxy_site.private_key_path,
                &proxy_site.portal_upstream,
                &proxy_site.authentication_upstream,
            ] {
                validate_absolute_path(path)?;
            }
            if let Some(path) = &proxy_site.bootstrap_upstream {
                validate_absolute_path(path)?;
            }
        }
        Ok(())
    }

    pub(crate) fn render(&self, paths: &CaddyPaths) -> Result<Vec<u8>, CaddyError> {
        self.validate()?;
        validate_absolute_path(&paths.state_directory)?;
        validate_absolute_path(&paths.runtime_directory)?;

        let mut sites = self.sites.iter().collect::<Vec<_>>();
        sites.sort_by(|left, right| left.site.id.cmp(&right.site.id));
        let mut servers = Map::new();
        let mut certificates = Vec::new();

        for proxy_site in sites {
            if !proxy_site.site.enabled {
                continue;
            }
            let certificate_tag = format!("site-{}", proxy_site.site.id);
            certificates.push(json!({
                "certificate": path_text(&proxy_site.certificate_path)?,
                "key": path_text(&proxy_site.private_key_path)?,
                "tags": [certificate_tag],
            }));

            if let Some(bootstrap_upstream) = &proxy_site.bootstrap_upstream {
                let server_name = server_name(&proxy_site.site.id, 80);
                servers.insert(
                    server_name,
                    bootstrap_server(
                        paths,
                        &proxy_site.site.id,
                        &proxy_site.onion_hostname,
                        bootstrap_upstream,
                    )?,
                );
            }

            servers.insert(
                server_name(&proxy_site.site.id, 443),
                tls_server(
                    paths,
                    proxy_site,
                    443,
                    &unix_reverse_proxy(&proxy_site.portal_upstream)?,
                    &certificate_tag,
                )?,
            );

            let mut mappings = proxy_site
                .site
                .mappings
                .iter()
                .filter(|mapping| mapping.enabled)
                .collect::<Vec<_>>();
            mappings.sort_by(|left, right| {
                left.virtual_port
                    .cmp(&right.virtual_port)
                    .then_with(|| left.id.cmp(&right.id))
            });
            for mapping in mappings {
                servers.insert(
                    server_name(&proxy_site.site.id, mapping.virtual_port),
                    tls_server(
                        paths,
                        proxy_site,
                        mapping.virtual_port,
                        &protected_mapping_handlers(proxy_site, mapping)?,
                        &certificate_tag,
                    )?,
                );
            }
        }

        let mut apps = Map::new();
        apps.insert("http".to_owned(), json!({ "servers": servers }));
        if !certificates.is_empty() {
            apps.insert(
                "tls".to_owned(),
                json!({ "certificates": { "load_files": certificates } }),
            );
        }

        let document = json!({
            "admin": {
                "listen": unix_listener(&paths.admin_socket(), 0o220)?,
                "config": { "persist": false },
            },
            "apps": apps,
        });
        let mut rendered = serde_json::to_vec_pretty(&document)?;
        rendered.push(b'\n');
        Ok(rendered)
    }
}

fn bootstrap_server(
    paths: &CaddyPaths,
    site_id: &SiteId,
    onion_hostname: &str,
    upstream: &Path,
) -> Result<Value, CaddyError> {
    Ok(json!({
        "listen": [unix_listener(&paths.site_socket(site_id, 80), 0o220)?],
        "routes": [
            {
                "match": [{
                    "host": [onion_hostname],
                    "method": ["GET", "HEAD"],
                }],
                "handle": [
                    sanitize_headers(),
                    unix_reverse_proxy(upstream)?,
                ],
                "terminal": true,
            },
            {
                "handle": [{
                    "handler": "static_response",
                    "status_code": 404,
                }],
                "terminal": true,
            },
        ],
        "errors": generic_errors(),
        "automatic_https": { "disable": true },
        "protocols": ["h1"],
    }))
}

fn tls_server(
    paths: &CaddyPaths,
    proxy_site: &ProxySite,
    virtual_port: u16,
    terminal_handler: &Value,
    certificate_tag: &str,
) -> Result<Value, CaddyError> {
    Ok(json!({
        "listen": [unix_listener(
            &paths.site_socket(&proxy_site.site.id, virtual_port),
            0o220,
        )?],
        "routes": [{
            "handle": [
                sanitize_headers(),
                forwarding_headers(),
                terminal_handler,
            ],
            "terminal": true,
        }],
        "errors": generic_errors(),
        "tls_connection_policies": [
            {
                "match": { "sni": [proxy_site.onion_hostname] },
                "certificate_selection": { "all_tags": [certificate_tag] },
                "protocol_min": "tls1.2",
                "protocol_max": "tls1.3",
            },
            { "drop": true },
        ],
        "automatic_https": { "disable": true },
        "strict_sni_host": true,
        "trusted_proxies_unix": true,
        "protocols": ["h1", "h2"],
        "enable_full_duplex": true,
        "read_header_timeout": "30s",
        "idle_timeout": "5m",
        "max_header_bytes": 1_048_576,
    }))
}

fn protected_mapping_handlers(
    proxy_site: &ProxySite,
    mapping: &Mapping,
) -> Result<Value, CaddyError> {
    let authentication = json!({
        "handler": "reverse_proxy",
        "upstreams": [{
            "dial": unix_dial(&proxy_site.authentication_upstream)?,
        }],
        "rewrite": {
            "method": "GET",
            "uri": "/authorize?",
        },
        "headers": {
            "request": {
                "set": {
                    "X-Forwarded-Method": ["{http.request.method}"],
                    "X-Forwarded-Uri": ["{http.request.uri}"],
                    "X-Forwarded-Host": ["{http.request.host}"],
                    "X-Forwarded-Proto": ["https"],
                    "X-Torkitten-Site": [proxy_site.site.id.as_str()],
                    "X-Torkitten-Mapping": [mapping.id.as_str()],
                },
            },
        },
        "handle_response": [{
            "match": { "status_code": [2] },
            "routes": [{
                "handle": [{ "handler": "vars" }],
            }],
        }],
    });
    let upstream = mapping_reverse_proxy(mapping)?;
    Ok(json!({
        "handler": "subroute",
        "routes": [{
            "handle": [authentication, upstream],
        }],
    }))
}

fn mapping_reverse_proxy(mapping: &Mapping) -> Result<Value, CaddyError> {
    let dial = match &mapping.target {
        MappingTarget::Tcp { address, port, .. } => SocketAddr::new(*address, *port).to_string(),
        MappingTarget::Unix { path, .. } => unix_dial(path)?,
    };
    let transport = match &mapping.target {
        MappingTarget::Tcp { transport, .. } | MappingTarget::Unix { transport, .. } => transport,
    };
    let mut handler = json!({
        "handler": "reverse_proxy",
        "upstreams": [{ "dial": dial }],
        "stream_close_delay": "5m",
    });
    match transport {
        Transport::Http => {}
        Transport::Https => {
            handler["transport"] = json!({
                "protocol": "http",
                "tls": {},
            });
        }
        Transport::H2c => {
            handler["transport"] = json!({
                "protocol": "http",
                "versions": ["h2c"],
            });
        }
    }
    Ok(handler)
}

fn unix_reverse_proxy(path: &Path) -> Result<Value, CaddyError> {
    Ok(json!({
        "handler": "reverse_proxy",
        "upstreams": [{ "dial": unix_dial(path)? }],
        "stream_close_delay": "5m",
    }))
}

fn sanitize_headers() -> Value {
    json!({
        "handler": "headers",
        "request": {
            "delete": [
                "Forwarded",
                "X-Forwarded-*",
                "X-Real-IP",
                "X-Torkitten-*",
            ],
        },
    })
}

fn forwarding_headers() -> Value {
    json!({
        "handler": "headers",
        "request": {
            "set": {
                "X-Forwarded-Host": ["{http.request.host}"],
                "X-Forwarded-Proto": ["https"],
            },
        },
    })
}

fn generic_errors() -> Value {
    json!({
        "routes": [{
            "handle": [{
                "handler": "static_response",
                "status_code": 503,
                "body": "Access temporarily unavailable\n",
                "headers": {
                    "Content-Type": ["text/plain; charset=utf-8"],
                    "Cache-Control": ["no-store"],
                },
            }],
            "terminal": true,
        }],
    })
}

fn server_name(site_id: &SiteId, virtual_port: u16) -> String {
    format!("site-{site_id}-port-{virtual_port}")
}

fn unix_listener(path: &Path, mode: u32) -> Result<String, CaddyError> {
    Ok(format!("{}|{mode:04o}", unix_dial(path)?))
}

fn unix_dial(path: &Path) -> Result<String, CaddyError> {
    validate_absolute_path(path)?;
    Ok(format!("unix/{}", path_text(path)?))
}

fn path_text(path: &Path) -> Result<&str, CaddyError> {
    path.to_str()
        .ok_or_else(|| CaddyError::InvalidPath(path.to_path_buf()))
}

fn validate_absolute_path(path: &Path) -> Result<(), CaddyError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
        || path_text(path)?.contains(['\n', '\r', '\0', '|'])
    {
        return Err(CaddyError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_onion_hostname(hostname: &str) -> Result<(), CaddyError> {
    let service_id = hostname.strip_suffix(".onion");
    let valid = service_id.is_some_and(|service_id| {
        service_id.len() == 56
            && service_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    });
    if valid {
        Ok(())
    } else {
        Err(CaddyError::InvalidOnionHostname(hostname.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use torkitten_core::{MappingId, MappingTarget};

    use super::*;

    const ALPHA_ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
    const BETA_ONION: &str = "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion";

    fn mapping(id: &str, virtual_port: u16, enabled: bool) -> Mapping {
        Mapping {
            id: MappingId::new(id).unwrap(),
            display_name: id.to_owned(),
            virtual_port,
            target: MappingTarget::Tcp {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 3000,
                transport: Transport::Http,
            },
            enabled,
        }
    }

    fn proxy_site(id: &str, hostname: &str, enabled: bool) -> ProxySite {
        ProxySite {
            site: Site {
                id: SiteId::new(id).unwrap(),
                display_name: format!("Site {id}"),
                enabled,
                mappings: vec![mapping("app", 8443, true), mapping("disabled", 8444, false)],
            },
            onion_hostname: hostname.to_owned(),
            certificate_path: PathBuf::from(format!("/state/{id}.crt")),
            private_key_path: PathBuf::from(format!("/state/{id}.key")),
            portal_upstream: PathBuf::from(format!("/run/{id}-portal.sock")),
            authentication_upstream: PathBuf::from(format!("/run/{id}-auth.sock")),
            bootstrap_upstream: Some(PathBuf::from(format!("/run/{id}-bootstrap.sock"))),
        }
    }

    fn paths() -> CaddyPaths {
        CaddyPaths::new("/opt/torkitten/libexec/caddy", "/state", "/run/torkitten")
    }

    #[test]
    fn renders_only_enabled_sites_and_mappings() {
        let config = ProxyConfig {
            sites: vec![
                proxy_site("beta", BETA_ONION, false),
                proxy_site("alpha", ALPHA_ONION, true),
            ],
        };
        let document: Value = serde_json::from_slice(&config.render(&paths()).unwrap()).unwrap();
        let servers = document["apps"]["http"]["servers"].as_object().unwrap();
        assert!(servers.contains_key("site-alpha-port-80"));
        assert_eq!(
            servers["site-alpha-port-80"]["automatic_https"]["disable"],
            true
        );
        assert!(servers.contains_key("site-alpha-port-443"));
        assert!(servers.contains_key("site-alpha-port-8443"));
        assert!(!servers.contains_key("site-alpha-port-8444"));
        assert!(!servers.keys().any(|name| name.contains("beta")));
    }

    #[test]
    fn mapping_authentication_is_fail_closed_and_precedes_upstream() {
        let config = ProxyConfig {
            sites: vec![proxy_site("alpha", ALPHA_ONION, true)],
        };
        let document: Value = serde_json::from_slice(&config.render(&paths()).unwrap()).unwrap();
        let handles =
            document["apps"]["http"]["servers"]["site-alpha-port-8443"]["routes"][0]["handle"]
                .as_array()
                .unwrap();
        assert_eq!(handles[0]["handler"], "headers");
        assert_eq!(handles[1]["handler"], "headers");
        assert_eq!(handles[2]["handler"], "subroute");
        let protected = handles[2]["routes"][0]["handle"].as_array().unwrap();
        assert_eq!(protected[0]["handler"], "reverse_proxy");
        assert_eq!(protected[0]["rewrite"]["uri"], "/authorize?");
        assert_eq!(protected[1]["handler"], "reverse_proxy");
        assert_eq!(protected[1]["upstreams"][0]["dial"], "127.0.0.1:3000");
    }

    #[test]
    fn rendering_is_deterministic_across_input_order() {
        let alpha = proxy_site("alpha", ALPHA_ONION, true);
        let beta = proxy_site("beta", BETA_ONION, true);
        let first = ProxyConfig {
            sites: vec![alpha.clone(), beta.clone()],
        };
        let second = ProxyConfig {
            sites: vec![beta, alpha],
        };
        assert_eq!(
            first.render(&paths()).unwrap(),
            second.render(&paths()).unwrap()
        );
    }

    #[test]
    fn rejects_duplicate_hostnames_and_unsafe_paths() {
        let mut duplicate = proxy_site("beta", ALPHA_ONION, true);
        duplicate.portal_upstream = PathBuf::from("/run/beta.sock");
        let config = ProxyConfig {
            sites: vec![proxy_site("alpha", ALPHA_ONION, true), duplicate],
        };
        assert!(matches!(
            config.validate(),
            Err(CaddyError::DuplicateOnionHostname(_))
        ));

        let mut unsafe_site = proxy_site("alpha", ALPHA_ONION, true);
        unsafe_site.private_key_path = PathBuf::from("../private.key");
        assert!(matches!(
            ProxyConfig {
                sites: vec![unsafe_site]
            }
            .validate(),
            Err(CaddyError::InvalidPath(_))
        ));
    }
}
