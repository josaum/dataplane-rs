//! Dependency-light authentication for Arrow Flight request metadata.

use std::{
    borrow::Cow,
    ffi::OsString,
    fmt, io,
    path::{Path, PathBuf},
};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::{
    Request, Status,
    metadata::{Ascii, MetadataMap, MetadataValue},
};

/// Clock skew, in seconds, tolerated when checking `exp`.
///
/// Matches the `jsonwebtoken` default so naming it changes no behavior. A
/// token minted for 300 seconds is therefore accepted for up to 360. Raising
/// it lengthens the life of every stolen token; lowering it starts refusing
/// tokens from hosts whose clocks drift.
const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;

/// Shortest HS256 secret, in bytes, that local workload minting accepts.
///
/// HS256 keys shorter than the 256-bit hash output can be brute-forced
/// offline from one captured token (RFC 7518 section 3.2).
const MIN_MINT_HS256_SECRET_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthClaim {
    pub sub: String,
    pub tenant_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub iss: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub require_auth: bool,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub es256_public_key_pem: Option<String>,
    pub legacy_hs256_secret: Option<String>,
    pub allow_legacy_hs256: bool,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("require_auth", &self.require_auth)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field(
                "es256_public_key_pem",
                &self.es256_public_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "legacy_hs256_secret",
                &self.legacy_hs256_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allow_legacy_hs256", &self.allow_legacy_hs256)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing bearer token")]
    MissingBearer,
    #[error("missing outbound authorization metadata")]
    MissingClientAuthorization,
    #[error("invalid outbound authorization metadata")]
    InvalidClientAuthorization,
    #[error("no configured signing material")]
    MissingConfig,
    #[error("invalid signing material or auth policy")]
    InvalidConfig,
    #[error("token validation failed")]
    InvalidToken,
    /// A boolean switch holds a value outside the documented set.
    ///
    /// Only the variable name is carried; the offending value is never echoed.
    #[error("{name} must be one of 1, true, yes, on, 0, false, no, off (or unset)")]
    InvalidFlag { name: &'static str },
    /// A server-side variable holds bytes that are not valid Unicode.
    #[error("{name} is not valid Unicode")]
    NonUnicodeEnv { name: &'static str },
    /// The configured public-key file could not be read.
    ///
    /// Carries the configured path and the I/O error kind, never file contents.
    #[error("cannot read FLIGHT_JWT_PUBLIC_KEY_PATH {}: {kind}", path.display())]
    KeyFileUnreadable { path: PathBuf, kind: io::ErrorKind },
    /// A server-side variable is set under a name this crate no longer reads.
    ///
    /// Ignoring it could start a server with authentication off that its
    /// operator configured to require it, so loading refuses instead.
    #[error("{old} was renamed to {new}; set {new} and remove {old}")]
    RenamedEnv {
        old: &'static str,
        new: &'static str,
    },
}

/// Validated outbound Flight authorization metadata with redacted debug output.
#[derive(Clone)]
pub struct FlightAuthorizationMetadata {
    value: MetadataValue<Ascii>,
}

impl fmt::Debug for FlightAuthorizationMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FlightAuthorizationMetadata")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl FlightAuthorizationMetadata {
    /// Resolve optional metadata from already-loaded values.
    ///
    /// The explicit header wins. The bearer-token value is deliberately raw
    /// and receives exactly one canonical `Bearer ` prefix.
    pub fn from_values(
        explicit_header: Option<&str>,
        raw_bearer_token: Option<&str>,
    ) -> Result<Option<Self>, AuthError> {
        let explicit_header = explicit_header
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let raw_bearer_token = raw_bearer_token
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let header = if let Some(explicit_header) = explicit_header {
            Cow::Borrowed(explicit_header)
        } else if let Some(raw_bearer_token) = raw_bearer_token {
            Cow::Owned(format!("Bearer {raw_bearer_token}"))
        } else {
            return Ok(None);
        };
        let mut value = MetadataValue::try_from(header.as_ref())
            .map_err(|_| AuthError::InvalidClientAuthorization)?;
        value.set_sensitive(true);
        Ok(Some(Self { value }))
    }

    /// Resolve required metadata from already-loaded values.
    pub fn from_values_required(
        explicit_header: Option<&str>,
        raw_bearer_token: Option<&str>,
    ) -> Result<Self, AuthError> {
        Self::from_values(explicit_header, raw_bearer_token)?
            .ok_or(AuthError::MissingClientAuthorization)
    }

    /// Resolve optional metadata from the canonical process environment.
    pub fn from_env() -> Result<Option<Self>, AuthError> {
        Self::from_env_source(client_auth_env)
    }

    /// Resolve required metadata before a client attempts network I/O.
    pub fn from_env_required() -> Result<Self, AuthError> {
        Self::from_env()?.ok_or(AuthError::MissingClientAuthorization)
    }

    /// Insert exactly one canonical authorization value into an existing request.
    pub fn apply<T>(&self, request: &mut Request<T>) {
        request
            .metadata_mut()
            .insert("authorization", self.value.clone());
    }

    /// Build a request containing exactly one canonical authorization value.
    pub fn request<T>(&self, payload: T) -> Request<T> {
        let mut request = Request::new(payload);
        self.apply(&mut request);
        request
    }

    fn from_env_source<F>(mut read: F) -> Result<Option<Self>, AuthError>
    where
        F: FnMut(&str) -> Result<Option<String>, AuthError>,
    {
        let explicit_header = read("FLIGHT_AUTHORIZATION")?;
        if explicit_header
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
        {
            return Self::from_values(explicit_header.as_deref(), None);
        }
        let raw_bearer_token = read("FLIGHT_BEARER_TOKEN")?;
        Self::from_values(explicit_header.as_deref(), raw_bearer_token.as_deref())
    }
}

/// Mints a short-lived, tenant-scoped authorization for a co-located Flight client.
///
/// The token is HS256-signed with `secret`, issued at `now` (Unix seconds),
/// and valid for 300 seconds; the second tuple element is its expiry. The
/// returned metadata is redacted by its `Debug` contract; callers cache it in
/// memory and refresh before the expiry.
///
/// `secret` is used in the same trimmed form the verifier uses, so a
/// `JWT_SECRET` with a trailing newline signs and verifies under one key.
///
/// # Errors
///
/// Returns [`AuthError::InvalidConfig`] when the trimmed secret is shorter
/// than 32 bytes, when `tenant_id` is blank or the wildcard `*`, or when
/// `subject` is blank.
pub fn mint_local_workload_authorization(
    secret: &str,
    tenant_id: &str,
    subject: &str,
    now: u64,
) -> Result<(FlightAuthorizationMetadata, u64), AuthError> {
    let secret = canonical_hs256_secret(secret).ok_or(AuthError::InvalidConfig)?;
    let tenant_id = tenant_id.trim();
    let subject = subject.trim();
    if secret.len() < MIN_MINT_HS256_SECRET_BYTES
        || tenant_id.is_empty()
        || tenant_id == "*"
        || subject.is_empty()
    {
        return Err(AuthError::InvalidConfig);
    }
    let expires_at = now.saturating_add(300);
    let claims = AuthClaim {
        sub: subject.to_owned(),
        tenant_id: tenant_id.to_owned(),
        roles: vec!["service".to_owned()],
        permissions: vec!["flight:invoke".to_owned()],
        iss: "dataplane".to_owned(),
        aud: "dataplane".to_owned(),
        iat: now,
        exp: expires_at,
        jti: uuid::Uuid::new_v4().to_string(),
        r#type: "access".to_owned(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AuthError::InvalidConfig)?;
    let metadata = FlightAuthorizationMetadata::from_values_required(None, Some(&token))?;
    Ok((metadata, expires_at))
}

fn client_auth_env(name: &str) -> Result<Option<String>, AuthError> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => os_string_into_client_auth(value).map(Some),
    }
}

fn os_string_into_client_auth(value: OsString) -> Result<String, AuthError> {
    value
        .into_string()
        .map_err(|_| AuthError::InvalidClientAuthorization)
}

/// Server-side variables under their previous names, with their current ones.
const RENAMED_SERVER_ENV: [(&str, &str); 6] = [
    ("ATLAS_FLIGHT_REQUIRE_AUTH", "FLIGHT_REQUIRE_AUTH"),
    (
        "ATLAS_FLIGHT_ALLOW_LEGACY_HS256",
        "FLIGHT_ALLOW_LEGACY_HS256",
    ),
    ("ATLAS_JWT_PUBLIC_KEY_PEM", "FLIGHT_JWT_PUBLIC_KEY_PEM"),
    ("ATLAS_JWT_PUBLIC_KEY_PATH", "FLIGHT_JWT_PUBLIC_KEY_PATH"),
    ("ATLAS_FLIGHT_ISSUER", "FLIGHT_JWT_ISSUER"),
    ("ATLAS_FLIGHT_AUDIENCE", "FLIGHT_JWT_AUDIENCE"),
];

/// Refuses a server-side variable that is still set under its previous name.
///
/// A deployment that set `ATLAS_FLIGHT_REQUIRE_AUTH=1` and upgraded would
/// otherwise start with authentication off. An empty value counts as unset,
/// as everywhere else.
fn refuse_renamed_server_env<E>(env: &mut E) -> Result<(), AuthError>
where
    E: FnMut(&str) -> Option<OsString>,
{
    for (old, new) in RENAMED_SERVER_ENV {
        if server_env(env, old)?.is_some() {
            return Err(AuthError::RenamedEnv { old, new });
        }
    }
    Ok(())
}

/// Reads one server-side variable in its canonical form.
///
/// The single place where "set but empty" becomes "unset": the value is
/// trimmed and an empty result is `None`. Templates such as `.env.example`
/// ship `NAME=` lines, and treating those as real values made a valid ES256
/// setup refuse to start.
fn server_env<E>(env: &mut E, name: &'static str) -> Result<Option<String>, AuthError>
where
    E: FnMut(&str) -> Option<OsString>,
{
    let Some(value) = env(name) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| AuthError::NonUnicodeEnv { name })?;
    let trimmed = value.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

/// Reads one boolean switch, refusing anything outside the documented set.
///
/// Unset is `false`. An unrecognised value is an error rather than `false`
/// because for `FLIGHT_REQUIRE_AUTH` reading a typo as `false` turns
/// authentication off.
fn server_flag<E>(env: &mut E, name: &'static str) -> Result<bool, AuthError>
where
    E: FnMut(&str) -> Option<OsString>,
{
    const TRUE_VALUES: [&str; 4] = ["1", "true", "yes", "on"];
    const FALSE_VALUES: [&str; 4] = ["0", "false", "no", "off"];

    let Some(value) = server_env(env, name)? else {
        return Ok(false);
    };
    if TRUE_VALUES
        .iter()
        .any(|accepted| value.eq_ignore_ascii_case(accepted))
    {
        Ok(true)
    } else if FALSE_VALUES
        .iter()
        .any(|accepted| value.eq_ignore_ascii_case(accepted))
    {
        Ok(false)
    } else {
        Err(AuthError::InvalidFlag { name })
    }
}

/// Returns the HS256 secret in the one form used to both sign and verify.
///
/// Secret mounts and env files routinely append a newline. Minting used to
/// trim while verification did not, so one `JWT_SECRET` produced two keys and
/// every minted token was refused without a reason. A blank secret is `None`.
fn canonical_hs256_secret(secret: &str) -> Option<&str> {
    let secret = secret.trim();
    (!secret.is_empty()).then_some(secret)
}

/// Immutable, startup-validated verifier for inbound Flight metadata.
#[derive(Debug, Clone)]
pub struct FlightRequestAuthVerifier {
    config: AuthConfig,
}

impl FlightRequestAuthVerifier {
    /// Validates `config` once at startup and wraps it in a verifier.
    ///
    /// A config with `require_auth` off is accepted unchecked and yields a
    /// verifier that accepts every request; see [`Self::require_enabled`].
    ///
    /// # Errors
    ///
    /// - [`AuthError::InvalidConfig`] when the ES256 PEM does not parse or the
    ///   HS256 secret is present but blank.
    /// - [`AuthError::MissingConfig`] when authentication is required and
    ///   neither an ES256 key nor an opted-in HS256 secret is configured.
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        if config.require_auth {
            let has_es256 = config
                .es256_public_key_pem
                .as_deref()
                .is_some_and(|pem| !pem.trim().is_empty());
            let has_hs256 = config
                .legacy_hs256_secret
                .as_deref()
                .and_then(canonical_hs256_secret)
                .is_some();
            if let Some(pem) = config.es256_public_key_pem.as_deref() {
                DecodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| AuthError::InvalidConfig)?;
            }
            if config.legacy_hs256_secret.is_some() && !has_hs256 {
                return Err(AuthError::InvalidConfig);
            }
            if !has_es256 && !(config.allow_legacy_hs256 && has_hs256) {
                return Err(AuthError::MissingConfig);
            }
        }
        Ok(Self { config })
    }

    /// Loads the gateway-compatible Flight authentication settings from the environment.
    ///
    /// Every variable is trimmed, and a variable that is set but empty counts
    /// as unset, so a sourced `.env.example` behaves like an empty environment.
    ///
    /// - `FLIGHT_REQUIRE_AUTH` and `FLIGHT_ALLOW_LEGACY_HS256`
    ///   accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`, in any
    ///   ASCII case. Unset means `false`.
    /// - `FLIGHT_JWT_ISSUER` and `FLIGHT_JWT_AUDIENCE` scope accepted tokens.
    /// - `FLIGHT_JWT_PUBLIC_KEY_PEM` supplies the ES256 key inline. Only when it
    ///   is unset is the file named by `FLIGHT_JWT_PUBLIC_KEY_PATH` read.
    /// - `JWT_SECRET` is the legacy HS256 secret.
    ///
    /// With `FLIGHT_REQUIRE_AUTH` unset the returned verifier is
    /// disabled and accepts every request. A network-facing surface must call
    /// [`Self::from_env_required`] instead, which refuses that state.
    ///
    /// # Errors
    ///
    /// - [`AuthError::InvalidFlag`] when a switch holds any other value, so a
    ///   typo can never silently turn authentication off.
    /// - [`AuthError::NonUnicodeEnv`] when a variable is not valid Unicode.
    /// - [`AuthError::KeyFileUnreadable`] when the configured key file cannot
    ///   be read, even if HS256 material would otherwise let the service start.
    /// - [`AuthError::InvalidConfig`] or [`AuthError::MissingConfig`] as
    ///   reported by [`Self::new`].
    pub fn from_env() -> Result<Self, AuthError> {
        Self::from_env_source(
            |name| std::env::var_os(name),
            |path| std::fs::read_to_string(path),
        )
    }

    // Pure counterpart of `from_env`: tests inject the lookup and the file
    // reader, so they never mutate (or race on) the process environment.
    fn from_env_source<E, R>(mut env: E, read_key_file: R) -> Result<Self, AuthError>
    where
        E: FnMut(&str) -> Option<OsString>,
        R: FnOnce(&Path) -> io::Result<String>,
    {
        refuse_renamed_server_env(&mut env)?;
        let require_auth = server_flag(&mut env, "FLIGHT_REQUIRE_AUTH")?;
        let allow_legacy_hs256 = server_flag(&mut env, "FLIGHT_ALLOW_LEGACY_HS256")?;
        let es256_public_key_pem = match server_env(&mut env, "FLIGHT_JWT_PUBLIC_KEY_PEM")? {
            Some(pem) => Some(pem),
            None => match server_env(&mut env, "FLIGHT_JWT_PUBLIC_KEY_PATH")? {
                Some(path) => {
                    let path = PathBuf::from(path);
                    // A key the operator asked for but that cannot be loaded
                    // is never treated as "no key": that would either report
                    // missing material or start HS256-only without a signal.
                    let pem =
                        read_key_file(&path).map_err(|error| AuthError::KeyFileUnreadable {
                            kind: error.kind(),
                            path,
                        })?;
                    Some(pem)
                }
                None => None,
            },
        };
        let config = AuthConfig {
            require_auth,
            issuer: server_env(&mut env, "FLIGHT_JWT_ISSUER")?,
            audience: server_env(&mut env, "FLIGHT_JWT_AUDIENCE")?,
            es256_public_key_pem,
            legacy_hs256_secret: server_env(&mut env, "JWT_SECRET")?,
            allow_legacy_hs256,
        };
        Self::new(config)
    }

    /// Load authentication for a surface advertising `ExistingAuth`.
    /// Such a surface must never start with authentication disabled.
    pub fn from_env_required() -> Result<Self, AuthError> {
        Self::from_env()?.require_enabled()
    }

    pub fn require_enabled(self) -> Result<Self, AuthError> {
        if !self.config.require_auth {
            return Err(AuthError::MissingConfig);
        }
        if self
            .config
            .issuer
            .as_deref()
            .is_none_or(|issuer| issuer.trim().is_empty())
            || self
                .config
                .audience
                .as_deref()
                .is_none_or(|audience| audience.trim().is_empty())
        {
            return Err(AuthError::MissingConfig);
        }
        Ok(self)
    }

    pub fn is_required(&self) -> bool {
        self.config.require_auth
    }

    /// Validate the single canonical `authorization` metadata value.
    /// Errors deliberately never include credentials or JWT decoder details.
    pub fn verify_metadata(&self, metadata: &MetadataMap) -> Result<(), Status> {
        self.verify_metadata_claim(metadata).map(|_| ())
    }

    /// Validate metadata and retain the claim for action-specific policy.
    ///
    /// A disabled verifier has no authenticated identity and therefore
    /// returns `None`; required production surfaces return exactly one claim.
    pub fn verify_metadata_claim(
        &self,
        metadata: &MetadataMap,
    ) -> Result<Option<AuthClaim>, Status> {
        if !self.config.require_auth {
            return Ok(None);
        }
        let mut values = metadata.get_all("authorization").iter();
        let header = values
            .next()
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
        if values.next().is_some() {
            return Err(Status::unauthenticated(
                "multiple authorization metadata values",
            ));
        }
        self.config
            .validate_bearer(header)
            .map(Some)
            .map_err(|_| Status::unauthenticated("invalid authorization metadata"))
    }
}

impl AuthConfig {
    pub fn disabled() -> Self {
        Self {
            require_auth: false,
            issuer: None,
            audience: None,
            es256_public_key_pem: None,
            legacy_hs256_secret: None,
            allow_legacy_hs256: false,
        }
    }

    /// Validates one `Bearer` header value and returns its claim.
    ///
    /// ES256 is tried first. HS256 is tried only when `allow_legacy_hs256` is
    /// set, with the secret in the same trimmed form that minting signs with.
    ///
    /// # Errors
    ///
    /// - [`AuthError::MissingConfig`] when `require_auth` is off.
    /// - [`AuthError::MissingBearer`] when the value has no `Bearer ` prefix.
    /// - [`AuthError::InvalidToken`] for every signature, expiry, issuer,
    ///   audience, or claim-policy failure; the reason is deliberately withheld.
    pub fn validate_bearer(&self, header: &str) -> Result<AuthClaim, AuthError> {
        if !self.require_auth {
            return Err(AuthError::MissingConfig);
        }

        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(AuthError::MissingBearer)?;

        if let Some(public_key) = &self.es256_public_key_pem {
            let validation = self.validation(Algorithm::ES256);
            if let Ok(data) = decode::<AuthClaim>(
                token,
                &DecodingKey::from_ec_pem(public_key.as_bytes())
                    .map_err(|_| AuthError::InvalidToken)?,
                &validation,
            ) {
                return Self::validate_claim_policy(data.claims);
            }
        }

        if self.allow_legacy_hs256
            && let Some(secret) = self
                .legacy_hs256_secret
                .as_deref()
                .and_then(canonical_hs256_secret)
        {
            let validation = self.validation(Algorithm::HS256);
            if let Ok(data) = decode::<AuthClaim>(
                token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &validation,
            ) {
                return Self::validate_claim_policy(data.claims);
            }
        }

        Err(AuthError::InvalidToken)
    }

    fn validation(&self, algorithm: Algorithm) -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.leeway = CLOCK_SKEW_LEEWAY_SECS;
        if let Some(issuer) = &self.issuer {
            validation.set_issuer(&[issuer.as_str()]);
        }
        if let Some(audience) = &self.audience {
            validation.set_audience(&[audience.as_str()]);
        } else {
            // Preserve the explicitly unscoped test/dev mode. Production
            // runtime surfaces configure the canonical audience.
            validation.validate_aud = false;
        }
        validation
    }

    fn validate_claim_policy(claim: AuthClaim) -> Result<AuthClaim, AuthError> {
        if claim.tenant_id.trim().is_empty()
            || claim.r#type != "access"
            || !claim
                .permissions
                .iter()
                .any(|permission| permission == "flight:invoke")
        {
            return Err(AuthError::InvalidToken);
        }
        Ok(claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_ES256_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeaB24Vky0rFr3157
/5LmvrFTw1MgJCQKaYjdukbll4yhRANCAASiBWLWleqMhTEtyIGlhx9kQA+zmuG6
QYp2+MAKG9ymlOp5hkVR2AoO9PFRkds64Z8q5fhpnzNcfOqZwx5R7ZNN
-----END PRIVATE KEY-----"#;
    const TEST_ES256_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEogVi1pXqjIUxLciBpYcfZEAPs5rh
ukGKdvjAChvcppTqeYZFUdgKDvTxUZHbOuGfKuX4aZ8zXHzqmcMeUe2TTQ==
-----END PUBLIC KEY-----"#;

    #[derive(Serialize)]
    struct CanonicalPythonAccessClaim {
        sub: &'static str,
        tenant_id: &'static str,
        roles: Vec<&'static str>,
        permissions: Vec<&'static str>,
        iss: &'static str,
        aud: &'static str,
        iat: u64,
        exp: u64,
        jti: &'static str,
        #[serde(rename = "type")]
        token_type: &'static str,
    }

    fn canonical_python_claim(now: u64) -> CanonicalPythonAccessClaim {
        CanonicalPythonAccessClaim {
            sub: "flight-service",
            tenant_id: "system",
            roles: vec!["service"],
            permissions: vec!["flight:invoke"],
            iss: "dataplane",
            aud: "dataplane",
            iat: now,
            exp: now + 60,
            jti: "python-service-jti",
            token_type: "access",
        }
    }

    fn verifier() -> FlightRequestAuthVerifier {
        FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            issuer: Some("dataplane".to_owned()),
            audience: Some("dataplane".to_owned()),
            es256_public_key_pem: None,
            legacy_hs256_secret: Some("test-only-secret".to_owned()),
            allow_legacy_hs256: true,
        })
        .unwrap()
    }

    #[test]
    fn required_auth_fails_closed_without_signing_material() {
        let error = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            ..AuthConfig::disabled()
        })
        .unwrap_err();
        assert!(matches!(error, AuthError::MissingConfig));
    }

    #[test]
    fn required_auth_rejects_malformed_or_empty_signing_material_at_startup() {
        let malformed = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            es256_public_key_pem: Some("not-a-pem".to_owned()),
            ..AuthConfig::disabled()
        })
        .unwrap_err();
        assert!(matches!(malformed, AuthError::InvalidConfig));

        let empty_hs = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            allow_legacy_hs256: true,
            legacy_hs256_secret: Some("  ".to_owned()),
            ..AuthConfig::disabled()
        })
        .unwrap_err();
        assert!(matches!(empty_hs, AuthError::InvalidConfig));
    }

    #[test]
    fn auth_configuration_and_verifier_debug_never_expose_hs256_secret() {
        let secret = "debug-must-not-leak-this-hs256-secret";
        let config = AuthConfig {
            require_auth: true,
            issuer: Some("dataplane".to_owned()),
            audience: Some("dataplane".to_owned()),
            es256_public_key_pem: None,
            legacy_hs256_secret: Some(secret.to_owned()),
            allow_legacy_hs256: true,
        };

        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains(secret));
        assert!(config_debug.contains("[REDACTED]"));

        let verifier = FlightRequestAuthVerifier::new(config).unwrap();
        let verifier_debug = format!("{verifier:?}");
        assert!(!verifier_debug.contains(secret));
        assert!(verifier_debug.contains("[REDACTED]"));
    }

    #[test]
    fn existing_auth_surface_rejects_disabled_verifier() {
        let error = FlightRequestAuthVerifier::new(AuthConfig::disabled())
            .unwrap()
            .require_enabled()
            .unwrap_err();
        assert!(matches!(error, AuthError::MissingConfig));
    }

    #[test]
    fn existing_auth_surface_requires_issuer_and_audience() {
        let error = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            es256_public_key_pem: None,
            legacy_hs256_secret: Some("test-only-secret".to_owned()),
            allow_legacy_hs256: true,
            issuer: None,
            audience: Some("dataplane".to_owned()),
        })
        .unwrap()
        .require_enabled()
        .unwrap_err();
        assert!(matches!(error, AuthError::MissingConfig));
    }

    #[test]
    fn metadata_requires_valid_bearer_and_redacts_failure() {
        let verifier = verifier();
        let missing = verifier.verify_metadata(&MetadataMap::new()).unwrap_err();
        assert_eq!(missing.code(), tonic::Code::Unauthenticated);

        let mut invalid = MetadataMap::new();
        invalid.insert(
            "authorization",
            MetadataValue::from_static("Bearer secret-token"),
        );
        let error = verifier.verify_metadata(&invalid).unwrap_err();
        assert_eq!(error.message(), "invalid authorization metadata");
        assert!(!error.message().contains("secret-token"));

        let mut duplicate = MetadataMap::new();
        duplicate.append("authorization", MetadataValue::from_static("Bearer one"));
        duplicate.append("authorization", MetadataValue::from_static("Bearer two"));
        let error = verifier.verify_metadata(&duplicate).unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "multiple authorization metadata values");
    }

    #[test]
    fn metadata_accepts_controlled_hs256_bearer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claim = AuthClaim {
            sub: "service".into(),
            tenant_id: "internal".into(),
            roles: vec![],
            permissions: vec!["flight:invoke".into()],
            iss: "dataplane".into(),
            aud: "dataplane".into(),
            iat: now,
            exp: now + 60,
            jti: "test-jti".into(),
            r#type: "access".into(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claim,
            &EncodingKey::from_secret(b"test-only-secret"),
        )
        .unwrap();
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let verified = verifier()
            .verify_metadata_claim(&metadata)
            .unwrap()
            .unwrap();
        assert_eq!(verified, claim);
    }

    fn verify_hs256_claim(claim: &CanonicalPythonAccessClaim) -> Result<(), Status> {
        let token = encode(
            &Header::new(Algorithm::HS256),
            claim,
            &EncodingKey::from_secret(b"test-only-secret"),
        )
        .unwrap();
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
        verifier().verify_metadata(&metadata)
    }

    #[test]
    fn canonical_python_service_token_does_not_require_duplicate_namespace_claim() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &canonical_python_claim(now),
            &EncodingKey::from_secret(b"test-only-secret"),
        )
        .unwrap();
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());

        verifier().verify_metadata(&metadata).unwrap();
    }

    #[test]
    fn canonical_claim_requires_nonempty_tenant_access_type_and_flight_permission() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut empty_tenant = canonical_python_claim(now);
        empty_tenant.tenant_id = "  ";
        assert!(verify_hs256_claim(&empty_tenant).is_err());

        let mut refresh = canonical_python_claim(now);
        refresh.token_type = "refresh";
        assert!(verify_hs256_claim(&refresh).is_err());

        let mut missing_permission = canonical_python_claim(now);
        missing_permission.permissions.clear();
        assert!(verify_hs256_claim(&missing_permission).is_err());
    }

    #[test]
    fn controlled_hs256_enforces_configured_canonical_issuer_and_audience() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut wrong_issuer = canonical_python_claim(now);
        wrong_issuer.iss = "other-issuer";
        assert!(verify_hs256_claim(&wrong_issuer).is_err());

        let mut wrong_audience = canonical_python_claim(now);
        wrong_audience.aud = "other-audience";
        assert!(verify_hs256_claim(&wrong_audience).is_err());
    }

    #[test]
    fn canonical_python_service_token_is_accepted_with_es256() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verify_es256_claim(&canonical_python_claim(now)).unwrap();
    }

    fn verify_es256_claim(claim: &CanonicalPythonAccessClaim) -> Result<(), Status> {
        let token = encode(
            &Header::new(Algorithm::ES256),
            claim,
            &EncodingKey::from_ec_pem(TEST_ES256_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let verifier = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            issuer: Some("dataplane".to_owned()),
            audience: Some("dataplane".to_owned()),
            es256_public_key_pem: Some(TEST_ES256_PUBLIC_KEY.to_owned()),
            legacy_hs256_secret: None,
            allow_legacy_hs256: false,
        })
        .unwrap();

        verifier.verify_metadata(&metadata)
    }

    #[test]
    fn es256_enforces_configured_canonical_issuer_and_audience() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut wrong_issuer = canonical_python_claim(now);
        wrong_issuer.iss = "other-issuer";
        assert!(verify_es256_claim(&wrong_issuer).is_err());

        let mut wrong_audience = canonical_python_claim(now);
        wrong_audience.aud = "other-audience";
        assert!(verify_es256_claim(&wrong_audience).is_err());
    }

    #[test]
    fn outbound_authorization_prefers_explicit_header_then_wraps_raw_bearer() {
        let explicit = FlightAuthorizationMetadata::from_values_required(
            Some("  Bearer explicit-token  "),
            Some("fallback-token"),
        )
        .unwrap();
        let explicit_request = explicit.request(());
        assert_eq!(
            explicit_request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer explicit-token"
        );
        assert!(
            explicit_request
                .metadata()
                .get("authorization")
                .unwrap()
                .is_sensitive()
        );
        assert!(!format!("{explicit_request:?}").contains("explicit-token"));

        let fallback =
            FlightAuthorizationMetadata::from_values_required(None, Some(" raw-token ")).unwrap();
        let fallback_request = fallback.request(());
        assert_eq!(
            fallback_request
                .metadata()
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer raw-token"
        );
    }

    #[test]
    fn outbound_environment_precedence_never_reads_an_unused_fallback() {
        let mut reads = Vec::new();
        let authorization = FlightAuthorizationMetadata::from_env_source(|name| {
            reads.push(name.to_owned());
            match name {
                "FLIGHT_AUTHORIZATION" => Ok(Some("Bearer explicit-token".to_owned())),
                "FLIGHT_BEARER_TOKEN" => Err(AuthError::InvalidClientAuthorization),
                _ => unreachable!(),
            }
        })
        .unwrap()
        .unwrap();

        assert_eq!(reads, ["FLIGHT_AUTHORIZATION"]);
        assert_eq!(
            authorization
                .request(())
                .metadata()
                .get("authorization")
                .unwrap(),
            "Bearer explicit-token"
        );
    }

    #[test]
    fn outbound_authorization_required_variant_fails_closed_when_missing() {
        assert!(
            FlightAuthorizationMetadata::from_values(None, None)
                .unwrap()
                .is_none()
        );
        let error = FlightAuthorizationMetadata::from_values_required(None, None).unwrap_err();
        assert!(matches!(error, AuthError::MissingClientAuthorization));
    }

    #[test]
    fn outbound_authorization_rejects_controls_and_redacts_debug_and_errors() {
        let secret = "sensitive-client-token";
        let authorization = FlightAuthorizationMetadata::from_values_required(
            Some(&format!("Bearer {secret}")),
            None,
        )
        .unwrap();
        assert!(!format!("{authorization:?}").contains(secret));

        let error = FlightAuthorizationMetadata::from_values_required(
            Some(&format!("Bearer {secret}\nsmuggled: value")),
            None,
        )
        .unwrap_err();
        assert!(matches!(error, AuthError::InvalidClientAuthorization));
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn applying_outbound_authorization_collapses_duplicates_to_exactly_one() {
        let authorization =
            FlightAuthorizationMetadata::from_values_required(Some("Bearer canonical-token"), None)
                .unwrap();
        let mut request = Request::new(());
        request.metadata_mut().append(
            "authorization",
            MetadataValue::from_static("Bearer stale-one"),
        );
        request.metadata_mut().append(
            "authorization",
            MetadataValue::from_static("Bearer stale-two"),
        );

        authorization.apply(&mut request);
        authorization.apply(&mut request);

        let values = request
            .metadata()
            .get_all("authorization")
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "Bearer canonical-token");
    }

    // ---- Refusal paths, configuration loading, and minting ----

    /// Exactly the 32-byte minimum that minting accepts.
    const WORKLOAD_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn bearer_metadata(token: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
        metadata
    }

    fn hs256_token<T: Serialize>(claim: &T, secret: &[u8]) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claim,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn es256_token<T: Serialize>(claim: &T) -> String {
        encode(
            &Header::new(Algorithm::ES256),
            claim,
            &EncodingKey::from_ec_pem(TEST_ES256_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// ES256 key plus an HS256 secret, with the legacy gate in either position.
    fn dual_material_verifier(allow_legacy_hs256: bool) -> FlightRequestAuthVerifier {
        FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            issuer: Some("dataplane".to_owned()),
            audience: Some("dataplane".to_owned()),
            es256_public_key_pem: Some(TEST_ES256_PUBLIC_KEY.to_owned()),
            legacy_hs256_secret: Some(WORKLOAD_SECRET.to_owned()),
            allow_legacy_hs256,
        })
        .unwrap()
    }

    fn assert_refused(verifier: &FlightRequestAuthVerifier, token: &str) {
        let error = verifier
            .verify_metadata(&bearer_metadata(token))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
        assert_eq!(error.message(), "invalid authorization metadata");
    }

    fn base64url(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let word = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for index in 0..=chunk.len() {
                output.push(char::from(
                    ALPHABET[((word >> (18 - 6 * index)) & 63) as usize],
                ));
            }
        }
        output
    }

    fn env_source<'a>(
        pairs: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    }

    fn key_file_must_not_be_read(_path: &Path) -> io::Result<String> {
        panic!("the public-key file must not be read in this configuration")
    }

    #[test]
    fn expired_token_is_refused_and_leeway_is_honoured() {
        let now = unix_now();

        let mut expired = canonical_python_claim(now - 600);
        expired.exp = now - 120;
        assert_refused(&verifier(), &hs256_token(&expired, b"test-only-secret"));
        assert_refused(&dual_material_verifier(false), &es256_token(&expired));

        // Inside the clock-skew leeway the same token is still accepted, which
        // pins that the refusal above is about expiry and nothing else.
        let mut skewed = canonical_python_claim(now - 600);
        skewed.exp = now - CLOCK_SKEW_LEEWAY_SECS / 2;
        verifier()
            .verify_metadata(&bearer_metadata(&hs256_token(&skewed, b"test-only-secret")))
            .unwrap();
    }

    #[test]
    fn token_without_issuer_or_audience_is_refused() {
        #[derive(Serialize)]
        struct Unscoped {
            sub: &'static str,
            tenant_id: &'static str,
            permissions: Vec<&'static str>,
            iat: u64,
            exp: u64,
            jti: &'static str,
            #[serde(rename = "type")]
            token_type: &'static str,
        }
        let now = unix_now();
        let claim = Unscoped {
            sub: "flight-service",
            tenant_id: "system",
            permissions: vec!["flight:invoke"],
            iat: now,
            exp: now + 60,
            jti: "unscoped-jti",
            token_type: "access",
        };
        assert_refused(&verifier(), &hs256_token(&claim, b"test-only-secret"));
    }

    #[test]
    fn well_formed_token_signed_with_the_wrong_key_is_refused() {
        let claim = canonical_python_claim(unix_now());
        assert_refused(&verifier(), &hs256_token(&claim, b"another-test-secret"));
    }

    #[test]
    fn hs256_token_signed_with_the_public_pem_is_refused() {
        let claim = canonical_python_claim(unix_now());
        let forged = hs256_token(&claim, TEST_ES256_PUBLIC_KEY.as_bytes());

        assert_refused(&dual_material_verifier(false), &forged);
        // Even with the legacy path open, the public key is not the secret.
        assert_refused(&dual_material_verifier(true), &forged);
        // The trimmed PEM is what an attacker would most plausibly try next.
        let forged_trimmed = hs256_token(&claim, TEST_ES256_PUBLIC_KEY.trim().as_bytes());
        assert_refused(&dual_material_verifier(true), &forged_trimmed);
    }

    #[test]
    fn unsigned_alg_none_token_is_refused() {
        let claim = canonical_python_claim(unix_now());
        let signed = hs256_token(&claim, WORKLOAD_SECRET.as_bytes());
        // Reuse the payload of a token the verifier accepts, so the only
        // difference is the header and the missing signature.
        dual_material_verifier(true)
            .verify_metadata(&bearer_metadata(&signed))
            .unwrap();
        let payload = signed.split('.').nth(1).unwrap();

        for header in [
            r#"{"alg":"none","typ":"JWT"}"#,
            r#"{"alg":"None","typ":"JWT"}"#,
            r#"{"alg":"NONE","typ":"JWT"}"#,
        ] {
            let unsigned = format!("{}.{payload}.", base64url(header.as_bytes()));
            assert_refused(&dual_material_verifier(true), &unsigned);
            assert_refused(&dual_material_verifier(false), &unsigned);
            assert_refused(&verifier(), &unsigned);
        }
    }

    #[test]
    fn legacy_hs256_gate_decides_whether_a_valid_hs256_token_is_accepted() {
        let claim = canonical_python_claim(unix_now());
        let token = hs256_token(&claim, WORKLOAD_SECRET.as_bytes());

        assert_refused(&dual_material_verifier(false), &token);
        dual_material_verifier(true)
            .verify_metadata(&bearer_metadata(&token))
            .unwrap();
    }

    #[test]
    fn minted_authorization_verifies_even_when_the_secret_has_surrounding_whitespace() {
        let now = unix_now();
        let raw_secret = format!("  {WORKLOAD_SECRET}\n");
        let (authorization, expires_at) =
            mint_local_workload_authorization(&raw_secret, " tenant-a ", " worker ", now).unwrap();
        assert_eq!(expires_at, now + 300);

        let verifier = FlightRequestAuthVerifier::new(AuthConfig {
            require_auth: true,
            issuer: Some("dataplane".to_owned()),
            audience: Some("dataplane".to_owned()),
            es256_public_key_pem: None,
            legacy_hs256_secret: Some(raw_secret),
            allow_legacy_hs256: true,
        })
        .unwrap();
        let claim = verifier
            .verify_metadata_claim(authorization.request(()).metadata())
            .unwrap()
            .unwrap();
        assert_eq!(claim.tenant_id, "tenant-a");
        assert_eq!(claim.sub, "worker");
        assert_eq!(claim.exp, expires_at);
        assert_eq!(claim.permissions, ["flight:invoke"]);
    }

    #[test]
    fn mint_refuses_short_secret_wildcard_or_blank_tenant_and_blank_subject() {
        let short_secret = &WORKLOAD_SECRET[..MIN_MINT_HS256_SECRET_BYTES - 1];
        // Padding must not let a short secret through.
        let padded_secret = format!("{short_secret}   ");
        for (secret, tenant_id, subject) in [
            (short_secret, "tenant-a", "worker"),
            (padded_secret.as_str(), "tenant-a", "worker"),
            ("", "tenant-a", "worker"),
            (WORKLOAD_SECRET, "*", "worker"),
            (WORKLOAD_SECRET, " * ", "worker"),
            (WORKLOAD_SECRET, "  ", "worker"),
            (WORKLOAD_SECRET, "tenant-a", "  "),
        ] {
            let error =
                mint_local_workload_authorization(secret, tenant_id, subject, 1).unwrap_err();
            assert!(
                matches!(error, AuthError::InvalidConfig),
                "tenant {tenant_id:?} subject {subject:?}"
            );
        }
    }

    #[test]
    fn require_auth_flag_accepts_only_the_documented_values() {
        for value in ["1", "true", "TRUE", "True", "yes", "YES", "on", " true\n"] {
            let pairs = [
                ("FLIGHT_REQUIRE_AUTH", value),
                ("FLIGHT_JWT_PUBLIC_KEY_PEM", TEST_ES256_PUBLIC_KEY),
            ];
            let verifier = FlightRequestAuthVerifier::from_env_source(
                env_source(&pairs),
                key_file_must_not_be_read,
            )
            .unwrap();
            assert!(verifier.is_required(), "{value:?} must enable auth");
        }

        for value in ["0", "false", "FALSE", "False", "no", "off", "", "  "] {
            let pairs = [("FLIGHT_REQUIRE_AUTH", value)];
            let verifier = FlightRequestAuthVerifier::from_env_source(
                env_source(&pairs),
                key_file_must_not_be_read,
            )
            .unwrap();
            assert!(!verifier.is_required(), "{value:?} must disable auth");
        }

        let unset =
            FlightRequestAuthVerifier::from_env_source(env_source(&[]), key_file_must_not_be_read)
                .unwrap();
        assert!(!unset.is_required());
    }

    #[test]
    fn unrecognised_flag_value_refuses_to_start_without_echoing_the_value() {
        const TYPO: &str = "distinctive-typo-value";
        for name in ["FLIGHT_REQUIRE_AUTH", "FLIGHT_ALLOW_LEGACY_HS256"] {
            for value in ["enabled", "tru", "2", "y", "true;", "t r u e", TYPO] {
                let pairs = [
                    (name, value),
                    ("FLIGHT_JWT_PUBLIC_KEY_PEM", TEST_ES256_PUBLIC_KEY),
                    ("JWT_SECRET", WORKLOAD_SECRET),
                ];
                let error = FlightRequestAuthVerifier::from_env_source(
                    env_source(&pairs),
                    key_file_must_not_be_read,
                )
                .unwrap_err();
                assert!(
                    matches!(error, AuthError::InvalidFlag { name: reported } if reported == name),
                    "{name}={value:?} gave {error:?}"
                );
                assert!(error.to_string().contains(name));
                // Short typos are substrings of the documented values the
                // message lists, so only the distinctive one can prove that
                // the offending value is not echoed.
                assert!(!error.to_string().contains(TYPO));
                assert!(!format!("{error:?}").contains(TYPO));
            }
        }
    }

    #[cfg(unix)]
    fn non_unicode_os_string() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b't', 0xff])
    }

    #[cfg(windows)]
    fn non_unicode_os_string() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[u16::from(b't'), 0xD800])
    }

    #[test]
    fn a_server_variable_under_its_previous_name_refuses_to_start() {
        for (old, new) in RENAMED_SERVER_ENV {
            let error = FlightRequestAuthVerifier::from_env_source(
                env_source(&[(old, "1"), ("FLIGHT_REQUIRE_AUTH", "1")]),
                key_file_must_not_be_read,
            )
            .unwrap_err();
            assert!(
                matches!(error, AuthError::RenamedEnv { old: o, new: n } if o == old && n == new),
                "{old}: {error}"
            );
        }
        // The case the refusal exists for: the old switch alone must not
        // start a server with authentication off.
        let error = FlightRequestAuthVerifier::from_env_source(
            env_source(&[("ATLAS_FLIGHT_REQUIRE_AUTH", "1")]),
            key_file_must_not_be_read,
        )
        .unwrap_err();
        assert!(matches!(error, AuthError::RenamedEnv { .. }));
        // An empty template line is unset, as for every other variable.
        assert!(
            FlightRequestAuthVerifier::from_env_source(
                env_source(&[("ATLAS_FLIGHT_REQUIRE_AUTH", "")]),
                key_file_must_not_be_read,
            )
            .is_ok()
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn non_unicode_server_variable_refuses_to_start() {
        let error = FlightRequestAuthVerifier::from_env_source(
            |name| (name == "FLIGHT_REQUIRE_AUTH").then(non_unicode_os_string),
            key_file_must_not_be_read,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            AuthError::NonUnicodeEnv {
                name: "FLIGHT_REQUIRE_AUTH"
            }
        ));

        let client = os_string_into_client_auth(non_unicode_os_string()).unwrap_err();
        assert!(matches!(client, AuthError::InvalidClientAuthorization));
    }

    /// The Flight block of the repository `.env.example`, verbatim.
    const ENV_EXAMPLE_SHAPE: [(&str, &str); 7] = [
        ("FLIGHT_REQUIRE_AUTH", "true"),
        ("FLIGHT_JWT_ISSUER", "dataplane"),
        ("FLIGHT_JWT_AUDIENCE", "dataplane"),
        ("FLIGHT_JWT_PUBLIC_KEY_PEM", ""),
        ("FLIGHT_JWT_PUBLIC_KEY_PATH", ""),
        ("FLIGHT_ALLOW_LEGACY_HS256", "false"),
        ("JWT_SECRET", ""),
    ];

    #[test]
    fn env_example_as_shipped_reports_missing_rather_than_invalid_material() {
        let error = FlightRequestAuthVerifier::from_env_source(
            env_source(&ENV_EXAMPLE_SHAPE),
            key_file_must_not_be_read,
        )
        .unwrap_err();
        assert!(matches!(error, AuthError::MissingConfig), "{error:?}");
    }

    #[test]
    fn env_example_with_only_the_key_path_filled_in_starts_with_es256() {
        let mut pairs = ENV_EXAMPLE_SHAPE;
        pairs[4] = ("FLIGHT_JWT_PUBLIC_KEY_PATH", " /run/secrets/flight.pem ");
        let mut read_paths = Vec::new();
        let verifier = FlightRequestAuthVerifier::from_env_source(env_source(&pairs), |path| {
            read_paths.push(path.to_path_buf());
            Ok(TEST_ES256_PUBLIC_KEY.to_owned())
        })
        .unwrap()
        .require_enabled()
        .unwrap();

        assert_eq!(read_paths, [PathBuf::from("/run/secrets/flight.pem")]);
        let claim = canonical_python_claim(unix_now());
        verifier
            .verify_metadata(&bearer_metadata(&es256_token(&claim)))
            .unwrap();
    }

    #[test]
    fn inline_pem_wins_and_the_key_path_is_never_consulted() {
        let pairs = [
            ("FLIGHT_REQUIRE_AUTH", "true"),
            ("FLIGHT_JWT_PUBLIC_KEY_PEM", TEST_ES256_PUBLIC_KEY),
            ("FLIGHT_JWT_PUBLIC_KEY_PATH", "/nonexistent/flight.pem"),
        ];
        let mut lookups = Vec::new();
        let mut source = env_source(&pairs);
        FlightRequestAuthVerifier::from_env_source(
            |name| {
                lookups.push(name.to_owned());
                source(name)
            },
            key_file_must_not_be_read,
        )
        .unwrap();
        assert!(
            lookups
                .iter()
                .any(|name| name == "FLIGHT_JWT_PUBLIC_KEY_PEM")
        );
        assert!(
            !lookups
                .iter()
                .any(|name| name == "FLIGHT_JWT_PUBLIC_KEY_PATH")
        );
    }

    #[test]
    fn unreadable_key_path_is_a_typed_error_naming_the_path() {
        let es256_only = [
            ("FLIGHT_REQUIRE_AUTH", "true"),
            ("FLIGHT_JWT_PUBLIC_KEY_PATH", "/nonexistent/flight.pem"),
        ];
        // A migration deployment must not quietly start HS256-only when the
        // ES256 key the operator asked for could not be loaded.
        let with_legacy_fallback = [
            ("FLIGHT_REQUIRE_AUTH", "true"),
            ("FLIGHT_JWT_PUBLIC_KEY_PATH", "/nonexistent/flight.pem"),
            ("FLIGHT_ALLOW_LEGACY_HS256", "true"),
            ("JWT_SECRET", WORKLOAD_SECRET),
        ];
        for pairs in [&es256_only[..], &with_legacy_fallback[..]] {
            let error = FlightRequestAuthVerifier::from_env_source(env_source(pairs), |_path| {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .unwrap_err();
            match &error {
                AuthError::KeyFileUnreadable { path, kind } => {
                    assert_eq!(path, Path::new("/nonexistent/flight.pem"));
                    assert_eq!(*kind, io::ErrorKind::PermissionDenied);
                }
                other => panic!("expected KeyFileUnreadable, got {other:?}"),
            }
            let message = error.to_string();
            assert!(message.contains("/nonexistent/flight.pem"), "{message}");
            assert!(message.contains("FLIGHT_JWT_PUBLIC_KEY_PATH"), "{message}");
            assert!(!message.contains(WORKLOAD_SECRET));
        }
    }

    #[test]
    fn real_filesystem_reader_reports_a_missing_key_file_as_not_found() {
        let missing = std::env::temp_dir().join(format!(
            "flight-auth-missing-key-{}-{}.pem",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let missing_text = missing.to_str().unwrap().to_owned();
        let pairs = [
            ("FLIGHT_REQUIRE_AUTH", "true"),
            ("FLIGHT_JWT_PUBLIC_KEY_PATH", missing_text.as_str()),
        ];
        let error = FlightRequestAuthVerifier::from_env_source(env_source(&pairs), |path| {
            std::fs::read_to_string(path)
        })
        .unwrap_err();
        assert!(matches!(
            error,
            AuthError::KeyFileUnreadable { ref path, kind: io::ErrorKind::NotFound } if *path == missing
        ));
    }
}
