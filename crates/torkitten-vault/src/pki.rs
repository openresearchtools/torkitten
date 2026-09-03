use std::{cmp::Ordering, fmt};

use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    pkey::{PKey, Private},
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use torkitten_core::SiteId;
use x509_parser::{extensions::ParsedExtension, parse_x509_certificate};
use zeroize::Zeroizing;

use crate::{Store, StoreError};

const ROOT_CERTIFICATE: &str = "pki/root-certificate-pem";
const ROOT_PRIVATE_KEY: &str = "pki/root-private-key-pem";
const INTERMEDIATE_CERTIFICATE: &str = "pki/intermediate-certificate-pem";
const INTERMEDIATE_PRIVATE_KEY: &str = "pki/intermediate-private-key-pem";
const ROOT_VALIDITY_DAYS: i64 = 3_650;
const INTERMEDIATE_VALIDITY_DAYS: i64 = 1_825;
const LEAF_VALIDITY_DAYS: i64 = 90;
const LEAF_RENEWAL_DAYS: i64 = 30;

pub struct TlsAuthority {
    root_certificate: String,
    intermediate_certificate: String,
    intermediate_private_key: Zeroizing<String>,
}

impl fmt::Debug for TlsAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsAuthority")
            .field("root_certificate", &"[PUBLIC CERTIFICATE]")
            .field("intermediate_certificate", &"[PUBLIC CERTIFICATE]")
            .field("intermediate_private_key", &"[REDACTED]")
            .finish()
    }
}

pub struct SiteCertificate {
    hostname: String,
    certificate_chain_pem: String,
    private_key_pem: Zeroizing<String>,
    not_before_unix: i64,
    not_after_unix: i64,
}

impl SiteCertificate {
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    #[must_use]
    pub fn certificate_chain_pem(&self) -> &str {
        &self.certificate_chain_pem
    }

    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    #[must_use]
    pub const fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }

    #[must_use]
    pub const fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }
}

impl fmt::Debug for SiteCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiteCertificate")
            .field("hostname", &self.hostname)
            .field("certificate_chain_pem", &"[PUBLIC CERTIFICATE CHAIN]")
            .field("private_key_pem", &"[REDACTED]")
            .field("not_before_unix", &self.not_before_unix)
            .field("not_after_unix", &self.not_after_unix)
            .finish()
    }
}

impl TlsAuthority {
    /// Loads the persistent private hierarchy, creating it only when no PKI
    /// state exists. Partial or invalid state fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid time, randomness, certificate generation,
    /// corrupt persisted material, or vault access failure.
    pub fn load_or_create(store: &mut Store, now_unix: i64) -> Result<Self, PkiError> {
        let root_certificate = store.get_secret(ROOT_CERTIFICATE)?;
        let root_private_key = store.get_secret(ROOT_PRIVATE_KEY)?;
        let intermediate_certificate = store.get_secret(INTERMEDIATE_CERTIFICATE)?;
        let intermediate_private_key = store.get_secret(INTERMEDIATE_PRIVATE_KEY)?;
        let present = [
            root_certificate.is_some(),
            root_private_key.is_some(),
            intermediate_certificate.is_some(),
            intermediate_private_key.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();

        if present == 0 {
            return Self::create(store, now_unix);
        }
        if present != 4 {
            return Err(PkiError::IncompleteHierarchy);
        }

        let (
            Some(root_certificate),
            Some(root_private_key),
            Some(intermediate_certificate),
            Some(intermediate_private_key),
        ) = (
            root_certificate,
            root_private_key,
            intermediate_certificate,
            intermediate_private_key,
        )
        else {
            return Err(PkiError::IncompleteHierarchy);
        };
        let root_certificate = decode_secret(&root_certificate, ROOT_CERTIFICATE)?;
        let root_private_key = decode_secret(&root_private_key, ROOT_PRIVATE_KEY)?;
        let intermediate_certificate =
            decode_secret(&intermediate_certificate, INTERMEDIATE_CERTIFICATE)?;
        let intermediate_private_key =
            decode_secret(&intermediate_private_key, INTERMEDIATE_PRIVATE_KEY)?;

        validate_hierarchy(
            &root_certificate,
            &root_private_key,
            &intermediate_certificate,
            &intermediate_private_key,
            now_unix,
        )?;
        Ok(Self {
            root_certificate: root_certificate.to_string(),
            intermediate_certificate: intermediate_certificate.to_string(),
            intermediate_private_key,
        })
    }

    fn create(store: &mut Store, now_unix: i64) -> Result<Self, PkiError> {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let root_private_key = Zeroizing::new(root_key.serialize_pem());
        let root = CertifiedIssuer::self_signed(
            ca_parameters(
                "Torkitten Private Root CA",
                BasicConstraints::Constrained(1),
                None,
                now_unix,
                ROOT_VALIDITY_DAYS,
            )?,
            root_key,
        )?;
        let root_certificate = root.pem();

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let intermediate_private_key = Zeroizing::new(intermediate_key.serialize_pem());
        let intermediate = CertifiedIssuer::signed_by(
            ca_parameters(
                "Torkitten Onion Intermediate CA",
                BasicConstraints::Constrained(0),
                Some(NameConstraints {
                    permitted_subtrees: vec![GeneralSubtree::DnsName(".onion".to_owned())],
                    excluded_subtrees: Vec::new(),
                }),
                now_unix,
                INTERMEDIATE_VALIDITY_DAYS,
            )?,
            intermediate_key,
            &root,
        )?;
        let intermediate_certificate = intermediate.pem();

        validate_hierarchy(
            &root_certificate,
            &root_private_key,
            &intermediate_certificate,
            &intermediate_private_key,
            now_unix,
        )?;
        store.put_secret_set(&[
            (ROOT_CERTIFICATE, root_certificate.as_bytes()),
            (ROOT_PRIVATE_KEY, root_private_key.as_bytes()),
            (
                INTERMEDIATE_CERTIFICATE,
                intermediate_certificate.as_bytes(),
            ),
            (
                INTERMEDIATE_PRIVATE_KEY,
                intermediate_private_key.as_bytes(),
            ),
        ])?;

        Ok(Self {
            root_certificate,
            intermediate_certificate,
            intermediate_private_key,
        })
    }

    /// Returns the only PKI artifact exposed by the certificate-bootstrap
    /// endpoint: the public root certificate.
    #[must_use]
    pub fn public_root_certificate_pem(&self) -> &str {
        &self.root_certificate
    }

    /// Loads a site's encrypted exact-host certificate, issuing or renewing it
    /// when missing, rotated to a new hostname, or inside the renewal window.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid onion hostnames, partial or corrupt state,
    /// certificate generation, randomness, or vault access failure.
    pub fn site_certificate(
        &self,
        store: &mut Store,
        site_id: &SiteId,
        hostname: &str,
        now_unix: i64,
    ) -> Result<SiteCertificate, PkiError> {
        validate_onion_hostname(hostname)?;
        if store.site(site_id)?.is_none() {
            return Err(StoreError::SiteNotFound(site_id.clone()).into());
        }
        let names = site_secret_names(site_id);
        let stored_hostname = store.get_secret(&names.hostname)?;
        let stored_chain = store.get_secret(&names.certificate_chain)?;
        let stored_key = store.get_secret(&names.private_key)?;
        let stored_not_before = store.get_secret(&names.not_before)?;
        let stored_not_after = store.get_secret(&names.not_after)?;
        let present = [
            stored_hostname.is_some(),
            stored_chain.is_some(),
            stored_key.is_some(),
            stored_not_before.is_some(),
            stored_not_after.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();

        if present == 0 {
            return self.issue_and_store_site_certificate(store, site_id, hostname, now_unix);
        }
        if present != 5 {
            return Err(PkiError::IncompleteSiteCertificate(site_id.clone()));
        }

        let (
            Some(stored_hostname),
            Some(stored_chain),
            Some(stored_key),
            Some(stored_not_before),
            Some(stored_not_after),
        ) = (
            stored_hostname,
            stored_chain,
            stored_key,
            stored_not_before,
            stored_not_after,
        )
        else {
            return Err(PkiError::IncompleteSiteCertificate(site_id.clone()));
        };
        let stored_hostname = decode_secret(&stored_hostname, "site hostname")?;
        let stored_chain = decode_secret(&stored_chain, "site certificate chain")?;
        let stored_key = decode_secret(&stored_key, "site private key")?;
        let stored_not_before =
            decode_timestamp(&stored_not_before, "site certificate not-before")?;
        let stored_not_after = decode_timestamp(&stored_not_after, "site certificate not-after")?;
        let renewal_deadline = now_unix
            .checked_add(LEAF_RENEWAL_DAYS * 86_400)
            .ok_or(PkiError::InvalidTimestamp(now_unix))?;

        if stored_hostname.as_str() != hostname || stored_not_after <= renewal_deadline {
            return self.issue_and_store_site_certificate(store, site_id, hostname, now_unix);
        }

        let certificate = SiteCertificate {
            hostname: stored_hostname.to_string(),
            certificate_chain_pem: stored_chain.to_string(),
            private_key_pem: stored_key,
            not_before_unix: stored_not_before,
            not_after_unix: stored_not_after,
        };
        self.validate_site_certificate(&certificate, now_unix)?;
        Ok(certificate)
    }

    fn issue_and_store_site_certificate(
        &self,
        store: &mut Store,
        site_id: &SiteId,
        hostname: &str,
        now_unix: i64,
    ) -> Result<SiteCertificate, PkiError> {
        let certificate = self.issue_site_certificate_unchecked(hostname, now_unix)?;
        self.validate_site_certificate(&certificate, now_unix)?;
        let names = site_secret_names(site_id);
        let not_before = certificate.not_before_unix.to_string();
        let not_after = certificate.not_after_unix.to_string();
        store.put_secret_set(&[
            (&names.hostname, hostname.as_bytes()),
            (
                &names.certificate_chain,
                certificate.certificate_chain_pem.as_bytes(),
            ),
            (&names.private_key, certificate.private_key_pem.as_bytes()),
            (&names.not_before, not_before.as_bytes()),
            (&names.not_after, not_after.as_bytes()),
        ])?;
        Ok(certificate)
    }

    fn issue_site_certificate_unchecked(
        &self,
        hostname: &str,
        now_unix: i64,
    ) -> Result<SiteCertificate, PkiError> {
        let intermediate_key = KeyPair::from_pem(&self.intermediate_private_key)?;
        let issuer = Issuer::from_ca_cert_pem(&self.intermediate_certificate, intermediate_key)?;
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let private_key_pem = Zeroizing::new(leaf_key.serialize_pem());
        let (not_before, not_after) = validity(now_unix, LEAF_VALIDITY_DAYS)?;
        let mut parameters = CertificateParams::new(vec![hostname.to_owned()])?;
        parameters.not_before = not_before;
        parameters.not_after = not_after;
        parameters.serial_number = Some(random_serial()?);
        parameters.distinguished_name = distinguished_name(hostname);
        parameters.is_ca = IsCa::ExplicitNoCa;
        parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        parameters.use_authority_key_identifier_extension = true;
        let leaf = parameters.signed_by(&leaf_key, &issuer)?;
        let certificate_chain_pem = format!("{}{}", leaf.pem(), self.intermediate_certificate);

        Ok(SiteCertificate {
            hostname: hostname.to_owned(),
            certificate_chain_pem,
            private_key_pem,
            not_before_unix: not_before.unix_timestamp(),
            not_after_unix: not_after.unix_timestamp(),
        })
    }

    fn validate_site_certificate(
        &self,
        certificate: &SiteCertificate,
        now_unix: i64,
    ) -> Result<(), PkiError> {
        let chain = X509::stack_from_pem(certificate.certificate_chain_pem.as_bytes())?;
        if chain.len() != 2 {
            return Err(PkiError::InvalidMaterial(
                "site certificate chain must contain exactly leaf and intermediate",
            ));
        }
        let leaf = &chain[0];
        let intermediate = &chain[1];
        let expected_intermediate = X509::from_pem(self.intermediate_certificate.as_bytes())?;
        if intermediate.to_der()? != expected_intermediate.to_der()? {
            return Err(PkiError::InvalidMaterial(
                "site certificate chain has an unexpected intermediate",
            ));
        }
        let leaf_key = PKey::private_key_from_pem(certificate.private_key_pem.as_bytes())?;
        let leaf_public_key = leaf.public_key()?;
        if !leaf_key.public_eq(&leaf_public_key) {
            return Err(PkiError::InvalidMaterial(
                "site certificate does not match its private key",
            ));
        }
        verify_site_chain(
            &self.root_certificate,
            leaf,
            intermediate,
            &certificate.hostname,
            now_unix,
        )
    }
}

fn ca_parameters(
    common_name: &str,
    constraints: BasicConstraints,
    name_constraints: Option<NameConstraints>,
    now_unix: i64,
    validity_days: i64,
) -> Result<CertificateParams, PkiError> {
    let (not_before, not_after) = validity(now_unix, validity_days)?;
    let mut parameters = CertificateParams::default();
    parameters.not_before = not_before;
    parameters.not_after = not_after;
    parameters.serial_number = Some(random_serial()?);
    parameters.distinguished_name = distinguished_name(common_name);
    parameters.is_ca = IsCa::Ca(constraints);
    parameters.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    parameters.name_constraints = name_constraints;
    parameters.use_authority_key_identifier_extension = true;
    Ok(parameters)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Torkitten");
    name.push(DnType::CommonName, common_name);
    name
}

fn validity(
    now_unix: i64,
    validity_days: i64,
) -> Result<(OffsetDateTime, OffsetDateTime), PkiError> {
    let now = OffsetDateTime::from_unix_timestamp(now_unix)
        .map_err(|_| PkiError::InvalidTimestamp(now_unix))?;
    let not_before = now
        .checked_sub(Duration::hours(24))
        .ok_or(PkiError::InvalidTimestamp(now_unix))?;
    let not_after = now
        .checked_add(Duration::days(validity_days))
        .ok_or(PkiError::InvalidTimestamp(now_unix))?;
    Ok((not_before, not_after))
}

fn random_serial() -> Result<SerialNumber, PkiError> {
    let mut bytes = [0_u8; 20];
    getrandom::fill(&mut bytes).map_err(PkiError::Random)?;
    bytes[0] &= 0x7f;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[19] = 1;
    }
    Ok(SerialNumber::from_slice(&bytes))
}

fn validate_hierarchy(
    root_certificate_pem: &str,
    root_private_key_pem: &str,
    intermediate_certificate_pem: &str,
    intermediate_private_key_pem: &str,
    now_unix: i64,
) -> Result<(), PkiError> {
    let root_certificate = X509::from_pem(root_certificate_pem.as_bytes())?;
    let root_private_key = PKey::private_key_from_pem(root_private_key_pem.as_bytes())?;
    validate_key_pair(&root_certificate, &root_private_key, "root")?;
    let root_public_key = root_certificate.public_key()?;
    if !root_certificate.verify(&root_public_key)? {
        return Err(PkiError::InvalidMaterial(
            "root certificate is not self-signed",
        ));
    }
    validate_ca_profile(&root_certificate, Some(1), false)?;
    validate_certificate_time(&root_certificate, now_unix, "root")?;

    let intermediate_certificate = X509::from_pem(intermediate_certificate_pem.as_bytes())?;
    let intermediate_private_key =
        PKey::private_key_from_pem(intermediate_private_key_pem.as_bytes())?;
    validate_key_pair(
        &intermediate_certificate,
        &intermediate_private_key,
        "intermediate",
    )?;
    if !intermediate_certificate.verify(&root_public_key)? {
        return Err(PkiError::InvalidMaterial(
            "intermediate certificate is not signed by the stored root",
        ));
    }
    validate_ca_profile(&intermediate_certificate, Some(0), true)?;
    validate_certificate_time(&intermediate_certificate, now_unix, "intermediate")
}

fn validate_key_pair(
    certificate: &X509,
    private_key: &PKey<Private>,
    label: &'static str,
) -> Result<(), PkiError> {
    let public_key = certificate.public_key()?;
    if private_key.public_eq(&public_key) {
        Ok(())
    } else if label == "root" {
        Err(PkiError::InvalidMaterial(
            "root certificate does not match its private key",
        ))
    } else {
        Err(PkiError::InvalidMaterial(
            "intermediate certificate does not match its private key",
        ))
    }
}

fn validate_ca_profile(
    certificate: &X509,
    expected_path_length: Option<u32>,
    require_onion_constraint: bool,
) -> Result<(), PkiError> {
    let der = certificate.to_der()?;
    let (_, parsed) = parse_x509_certificate(&der)
        .map_err(|_| PkiError::InvalidMaterial("certificate extensions cannot be parsed"))?;
    let basic = parsed
        .basic_constraints()
        .map_err(|_| PkiError::InvalidMaterial("duplicate or invalid basic constraints"))?
        .ok_or(PkiError::InvalidMaterial("CA has no basic constraints"))?;
    if !basic.critical || !basic.value.ca || basic.value.path_len_constraint != expected_path_length
    {
        return Err(PkiError::InvalidMaterial(
            "CA basic constraints are not fail-closed",
        ));
    }
    let usage = parsed
        .key_usage()
        .map_err(|_| PkiError::InvalidMaterial("duplicate or invalid key usage"))?
        .ok_or(PkiError::InvalidMaterial("CA has no key usage"))?;
    if !usage.critical || !usage.value.key_cert_sign() || !usage.value.crl_sign() {
        return Err(PkiError::InvalidMaterial(
            "CA key usage does not permit certificate and CRL signing",
        ));
    }
    if require_onion_constraint && !has_onion_name_constraint(&parsed) {
        return Err(PkiError::InvalidMaterial(
            "intermediate is not critically constrained to .onion names",
        ));
    }
    Ok(())
}

fn has_onion_name_constraint(certificate: &x509_parser::certificate::X509Certificate<'_>) -> bool {
    certificate.extensions().iter().any(|extension| {
        if !extension.critical {
            return false;
        }
        let ParsedExtension::NameConstraints(constraints) = extension.parsed_extension() else {
            return false;
        };
        let permitted_onion = constraints
            .permitted_subtrees
            .as_ref()
            .is_some_and(|subtrees| {
                subtrees.len() == 1
                    && matches!(
                        subtrees[0].base,
                        x509_parser::extensions::GeneralName::DNSName(".onion")
                    )
            });
        permitted_onion && constraints.excluded_subtrees.is_none()
    })
}

fn validate_certificate_time(
    certificate: &X509,
    now_unix: i64,
    label: &'static str,
) -> Result<(), PkiError> {
    let now = Asn1Time::from_unix(now_unix)?;
    let starts = certificate.not_before().compare(&now)?;
    let ends = certificate.not_after().compare(&now)?;
    if starts == Ordering::Greater || ends != Ordering::Greater {
        if label == "root" {
            Err(PkiError::InvalidMaterial(
                "root certificate is not currently valid",
            ))
        } else {
            Err(PkiError::InvalidMaterial(
                "intermediate certificate is not currently valid",
            ))
        }
    } else {
        Ok(())
    }
}

fn verify_site_chain(
    root_certificate_pem: &str,
    leaf: &X509,
    intermediate: &X509,
    hostname: &str,
    now_unix: i64,
) -> Result<(), PkiError> {
    let root = X509::from_pem(root_certificate_pem.as_bytes())?;
    let mut parameters = X509VerifyParam::new()?;
    parameters.set_host(hostname)?;
    parameters.set_time(now_unix);
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root)?;
    store.set_param(&parameters)?;
    let store = store.build();
    let mut chain = Stack::new()?;
    chain.push(intermediate.to_owned())?;
    let mut context = X509StoreContext::new()?;
    let valid = context.init(
        &store,
        leaf,
        &chain,
        openssl::x509::X509StoreContextRef::verify_cert,
    )?;
    if valid {
        Ok(())
    } else {
        Err(PkiError::InvalidMaterial(
            "site certificate chain or hostname is invalid",
        ))
    }
}

fn validate_onion_hostname(hostname: &str) -> Result<(), PkiError> {
    let Some(service_id) = hostname.strip_suffix(".onion") else {
        return Err(PkiError::InvalidOnionHostname(hostname.to_owned()));
    };
    let valid = service_id.len() == 56
        && service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'));
    if valid {
        Ok(())
    } else {
        Err(PkiError::InvalidOnionHostname(hostname.to_owned()))
    }
}

struct SiteSecretNames {
    hostname: String,
    certificate_chain: String,
    private_key: String,
    not_before: String,
    not_after: String,
}

fn site_secret_names(site_id: &SiteId) -> SiteSecretNames {
    let prefix = format!("pki/site/{}/", site_id.as_str());
    SiteSecretNames {
        hostname: format!("{prefix}hostname"),
        certificate_chain: format!("{prefix}certificate-chain-pem"),
        private_key: format!("{prefix}private-key-pem"),
        not_before: format!("{prefix}not-before-unix"),
        not_after: format!("{prefix}not-after-unix"),
    }
}

fn decode_secret(
    secret: &Zeroizing<Vec<u8>>,
    label: &'static str,
) -> Result<Zeroizing<String>, PkiError> {
    String::from_utf8(secret.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| PkiError::InvalidEncoding(label))
}

fn decode_timestamp(secret: &Zeroizing<Vec<u8>>, label: &'static str) -> Result<i64, PkiError> {
    let value = decode_secret(secret, label)?;
    value.parse().map_err(|_| PkiError::InvalidEncoding(label))
}

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("private certificate hierarchy is incomplete")]
    IncompleteHierarchy,
    #[error("certificate state for site {0} is incomplete")]
    IncompleteSiteCertificate(SiteId),
    #[error("invalid v3 onion hostname: {0}")]
    InvalidOnionHostname(String),
    #[error("invalid Unix timestamp for certificate issuance: {0}")]
    InvalidTimestamp(i64),
    #[error("stored {0} is not valid UTF-8 or a decimal timestamp")]
    InvalidEncoding(&'static str),
    #[error("invalid private certificate material: {0}")]
    InvalidMaterial(&'static str),
    #[error("operating-system randomness failed: {0}")]
    Random(getrandom::Error),
    #[error(transparent)]
    Certificate(#[from] rcgen::Error),
    #[error(transparent)]
    OpenSsl(#[from] ErrorStack),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use torkitten_core::Site;

    const NOW: i64 = 1_900_000_000;
    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    fn store() -> (tempfile::TempDir, Store) {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(temporary.path()).unwrap();
        (temporary, store)
    }

    fn put_site(store: &mut Store, id: &str) -> SiteId {
        let id = SiteId::new(id).unwrap();
        store
            .put_site(&Site {
                id: id.clone(),
                display_name: "Test site".to_owned(),
                enabled: true,
                mappings: Vec::new(),
            })
            .unwrap();
        id
    }

    #[test]
    fn persists_one_private_hierarchy_and_redacts_debug_output() {
        let (temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let root = authority.public_root_certificate_pem().to_owned();
        assert!(!format!("{authority:?}").contains("PRIVATE KEY"));
        drop(authority);
        drop(store);

        let mut reopened = Store::open(temporary.path()).unwrap();
        let authority = TlsAuthority::load_or_create(&mut reopened, NOW + 60).unwrap();
        assert_eq!(authority.public_root_certificate_pem(), root);
    }

    #[test]
    fn issues_persistent_exact_onion_certificates_and_rotates_with_identity() {
        let (_temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let site_id = put_site(&mut store, "alpha");
        let first = authority
            .site_certificate(&mut store, &site_id, ONION, NOW)
            .unwrap();
        let first_key = first.private_key_pem().to_owned();
        assert_eq!(first.hostname(), ONION);
        assert!(!format!("{first:?}").contains(&first_key));

        let loaded = authority
            .site_certificate(&mut store, &site_id, ONION, NOW + 60)
            .unwrap();
        assert_eq!(loaded.private_key_pem(), first_key);

        let rotated_hostname = format!("{}a.onion", &ONION[..55]);
        let rotated = authority
            .site_certificate(&mut store, &site_id, &rotated_hostname, NOW + 120)
            .unwrap();
        assert_ne!(rotated.private_key_pem(), first_key);
        assert_eq!(rotated.hostname(), rotated_hostname);
    }

    #[test]
    fn rejects_non_onion_leafs_and_enforces_name_constraint_cryptographically() {
        let (_temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let site_id = put_site(&mut store, "alpha");
        assert!(matches!(
            authority.site_certificate(&mut store, &site_id, "example.com", NOW),
            Err(PkiError::InvalidOnionHostname(_))
        ));

        let forbidden = authority
            .issue_site_certificate_unchecked("example.com", NOW)
            .unwrap();
        assert!(matches!(
            authority.validate_site_certificate(&forbidden, NOW),
            Err(PkiError::InvalidMaterial(_))
        ));
    }

    #[test]
    fn renews_leaf_before_expiration_without_rotating_the_root() {
        let (_temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let root = authority.public_root_certificate_pem().to_owned();
        let site_id = put_site(&mut store, "alpha");
        let first = authority
            .site_certificate(&mut store, &site_id, ONION, NOW)
            .unwrap();
        let first_key = first.private_key_pem().to_owned();

        let renewal_time = NOW + 61 * 86_400;
        let renewed = authority
            .site_certificate(&mut store, &site_id, ONION, renewal_time)
            .unwrap();
        assert_ne!(renewed.private_key_pem(), first_key);
        assert!(renewed.not_after_unix() > first.not_after_unix());
        assert_eq!(authority.public_root_certificate_pem(), root);
    }

    #[test]
    fn never_stores_private_keys_as_plaintext() {
        let (temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let site_id = put_site(&mut store, "alpha");
        let certificate = authority
            .site_certificate(&mut store, &site_id, ONION, NOW)
            .unwrap();
        let leaf_key = certificate.private_key_pem().as_bytes().to_vec();
        let intermediate_key = authority.intermediate_private_key.as_bytes().to_vec();
        drop(certificate);
        drop(authority);
        drop(store);

        for filename in ["state.sqlite3", "state.sqlite3-wal"] {
            let path = temporary.path().join(filename);
            if let Ok(database) = fs::read(path) {
                for private_key in [&leaf_key, &intermediate_key] {
                    assert!(
                        !database
                            .windows(private_key.len())
                            .any(|window| window == private_key.as_slice())
                    );
                }
            }
        }
    }

    #[test]
    fn fails_closed_for_partial_hierarchy() {
        let (_temporary, mut store) = store();
        store
            .put_secret(ROOT_CERTIFICATE, b"only one part")
            .unwrap();
        assert!(matches!(
            TlsAuthority::load_or_create(&mut store, NOW),
            Err(PkiError::IncompleteHierarchy)
        ));
    }

    #[test]
    fn removes_site_certificate_material_with_the_site() {
        let (_temporary, mut store) = store();
        let authority = TlsAuthority::load_or_create(&mut store, NOW).unwrap();
        let site_id = put_site(&mut store, "alpha");
        authority
            .site_certificate(&mut store, &site_id, ONION, NOW)
            .unwrap();
        let names = site_secret_names(&site_id);
        assert!(store.get_secret(&names.private_key).unwrap().is_some());

        assert!(store.remove_site(&site_id).unwrap());
        for name in [
            names.hostname,
            names.certificate_chain,
            names.private_key,
            names.not_before,
            names.not_after,
        ] {
            assert!(store.get_secret(&name).unwrap().is_none());
        }
    }
}
