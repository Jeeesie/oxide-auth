//! Provides the handling for Access Token Requests
use std::borrow::{Cow};
use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json;
use serde::{Serialize,Deserialize};

use primitives::grant::{Extensions, Grant};
use code_grant::error::{AccessTokenErrorType, AccessTokenError};
use std::string::String;
use primitives::registrar::Registrar;

/// Token Response
#[derive(Deserialize, Serialize)]
pub(crate) struct RegistarResponse {

    pub client_id: Option<String>,
    /// Error code
    #[serde(skip_serializing_if="Option::is_none")]
    pub error: Option<String>,
}

/// Trait based retrieval of parameters necessary for access token request handling.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    // The authorization code grant for which an access token is wanted.
    // fn code(&self) -> Option<Cow<str>>;

    // User:password of a basic authorization header.
    // fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)>;

    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;

    /// Valid request have the redirect url used to request the authorization code grant.
    fn redirect_uri(&self) -> Option<Cow<str>>;

    /// Valid requests have this set to "authorization_code"
    fn grant_type(&self) -> Option<Cow<str>>;

    // Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible. 
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Under these considerations, support must be explicitely enabled.
    fn allow_credentials_in_body(&self) -> bool {
        false
    }
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request and extension data to produce extension data.
    ///
    /// The input data comes from the extension data produced in the handling of the
    /// authorization code request.
    fn extend(&mut self, request: &dyn Request, data: Extensions) -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request, _: Extensions) -> std::result::Result<Extensions, ()> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to access token requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Get the client corresponding to some id.
    fn registrar(&self) -> &dyn Registrar;


    fn registrar_mut(&mut self) -> &mut dyn Registrar;

    // Get the authorizer from which we can recover the authorization.
    // fn authorizer(&mut self) -> &mut dyn Authorizer;

    // Return the issuer instance to create the access token.
    // fn issuer(&mut self) -> &mut dyn Issuer;

    // The system of used extension, extending responses.
    //
    // It is possible to use `&mut ()`.
    // fn extension(&mut self) -> & mut dyn Extension;
}

/// Defines actions for the response to an access token request.
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive(PrimitiveError),
}

/// The endpoint should have enough control over its primitives to find
/// out what has gone wrong, e.g. they may externall supply error 
/// information.
/// 
/// In this case, all previous results returned by the primitives are
/// included in the return value. Through this mechanism, one can
/// accomodate async handlers by implementing a sync-based result cache
/// that is filled with these partial values. In case only parts of the
/// outstanding futures, invoked during internal calls, are ready the
/// cache can be refilled through the error eliminating polls to already
/// sucessful futures.
///
/// Note that `token` is not included in this list, since the handler
/// can never fail after supplying a token to the backend.
pub struct PrimitiveError {
    /// The already extracted grant.
    ///
    /// You may reuse this, or more precisely you must to fulfill this exact request in case of
    /// an error recovery attempt.
    pub grant: Option<Grant>,

    // The extensions that were computed.
    // pub extensions: Option<Extensions>,
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Represents an access token, a refresh token and the associated scope for serialization.
pub struct RegistarClient(String, String);

impl Error {
    fn invalid() -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::default()
        })
    }

    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AccessTokenError> {
        match self {
            Error::Invalid(description) => Some(description.description()),
            Error::Unauthorized(description, _) => Some(description.description()),
            Error::Primitive(_) => None,
        }
    }
}

impl ErrorDescription {
    /// Convert the error into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(&self) -> String {
        let asmap = self.error
            .iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
    }

    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AccessTokenError {
        &mut self.error
    }
}

impl RegistarClient {
    /// Convert the token into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    // FIXME: rename to `into_json` or have `&self` argument.
    pub fn to_json(&self) -> String {

        // let remaining = self.0.until.signed_duration_since(Utc::now());
        let regist_response = RegistarResponse {
            client_id: None,
            error: None,
        };

        serde_json::to_string(&regist_response).unwrap()
    }
}

