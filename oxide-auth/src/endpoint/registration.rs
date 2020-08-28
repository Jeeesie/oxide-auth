use std::str::from_utf8;
use std::marker::PhantomData;

use code_grant::registration::{Error as RegistarError, Endpoint as RegistarEndpoint, Request as RegistarRequest, RegistarClient, Error};
use super::*;
use endpoint::{Endpoint, WebRequest, QueryParameter, WebResponse, OAuthError, Scopes, OwnerSolicitor, Template};
use std::borrow::Cow;
use endpoint::Extension as SuperExtension;
use primitives::registrar::{Client, ClientType, ClientMap, Registrar};
use primitives::issuer::Issuer;
use code_grant::error::{AccessTokenError, AuthorizationError};
use code_grant::resource::Error as ResourceError;

/// Offers access tokens to authenticated third parties.
///
/// After having received an authorization code from the resource owner, a client must
/// directly contact the OAuth endpoint–authenticating itself–to receive the access
/// token. The token is then used as authorization in requests to the resource. This
/// request MUST be protected by TLS.
///
/// Client credentials can be allowed to appear in the request body instead of being
/// required to be passed as HTTP Basic authorization. This is not recommended and must be
/// enabled explicitely. See [`allow_credentials_in_body`] for details.
///
/// [`allow_credentials_in_body`]: #method.allow_credentials_in_body
pub struct RegisterFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedRegister<E, R>,
    allow_credentials_in_body: bool,
}

struct WrappedRegister<E: Endpoint<R>, R: WebRequest> {
    inner: E, 
    extension_fallback: (),
    r_type: PhantomData<R>,
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    body: Cow<'a, dyn QueryParameter + 'static>,

    // /// The authorization tuple
    // authorization: Option<Authorization>,
    /// The client to regist
    client: Option<Client>,

    /// An error if one occurred.
    error: Option<FailParse<R::Error>>,

    /// The credentials-in-body flag from the flow.
    allow_credentials_in_body: bool,
}

struct Invalid;

enum FailParse<E> {
    Invalid,
    Err(E),
}

// struct Authorization(String, Vec<u8>);

impl<E, R> RegisterFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For 
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        // if endpoint.authorizer_mut().is_none() {
        //     return Err(endpoint.error(OAuthError::PrimitiveError));
        // }

        // if endpoint.issuer_mut().is_none() {
        //     return Err(endpoint.error(OAuthError::PrimitiveError));
        // }

        Ok(RegisterFlow {
            endpoint: WrappedRegister {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData
            },
            allow_credentials_in_body: false,
        })
    }

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible. 
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Thus support is disabled by default and must be explicitely enabled.
    pub fn allow_credentials_in_body(&mut self, allow: bool) {
        self.allow_credentials_in_body = allow;
    }

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the registrar, authorizer, or issuer returned by the endpoint is suddenly 
    /// `None` when previously it was `Some(_)`.
    pub fn execute(mut self, mut request: R) -> Result<R::Response, E::Error> {
/*
        let check_client = self.endpoint
            .registar_solicitor()
            .check_client();

        let client = match check_client{
            OwnerConsent::Regist(client) => Some(client),
            OwnerConsent::Denied => None
        };*/
        let r = self.endpoint.inner.registrar_mut().unwrap();
        println!("registar got. " );
        // if let Some(client) = client{
        //     r.regist(client);
        // }
        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";
        let client_url = "https://example.com";
        let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
                                                  "default".parse().unwrap(), private_passphrase);

        r.regist(private_client);

/*        match r.regist(client){
            Ok(_0) => {
                println!("register success. ");
            }
            Err(e) => {
                println!("register success. ");
            }
        }*/

        let mut response = self.endpoint.inner.response(&mut request, InnerTemplate::Ok.into())?;
        response.body_json("regist client success.")
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

/*
impl<E: Endpoint<R>, R: WebRequest> WrappedRegister<E, R> {
    fn registar_solicitor(&mut self) -> &mut dyn RegistarSolicitor<R> {
        self.inner.registar_solicitor().unwrap()
    }
}*/

impl<E: Endpoint<R>, R: WebRequest> RegistarEndpoint for WrappedRegister<E, R> {
    fn registrar(&self) -> &dyn Registrar {
        self.inner.registrar().unwrap()
    }

    fn registrar_mut(&mut self) -> &mut dyn Registrar {
        self.inner.registrar_mut().unwrap()
    }

    // fn authorizer(&mut self) -> &mut dyn Authorizer {
    //     self.inner.authorizer_mut().unwrap()
    // }

    // fn issuer(&mut self) -> &mut dyn Issuer {
    //     self.inner.issuer_mut().unwrap()
    // }

    // fn extension(&mut self) -> &mut dyn Extension {
    //     // self.inner.extension()
    //     //     .and_then(SuperExtension::access_token)
    //     //     .unwrap_or(&mut self.extension_fallback)
    //     self.inner.extension()
    // }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R, credentials: bool) -> Self {
        Self::new_or_fail(request, credentials)
            .unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R, credentials: bool)
        -> Result<Self, FailParse<R::Error>>
    {

        // let client = request.

        Ok(WrappedRequest {
            request: PhantomData,
            // body: request.urlbody().map_err(FailParse::Err)?,
            body: request.query().map_err(FailParse::Err)?,  //改为query接受参数
            // authorization,
            error: None,
            allow_credentials_in_body: credentials,
            client: None
        })
    }

    fn from_err(err: FailParse<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Cow::Owned(Default::default()),
            client: None,
            error: Some(err),
            allow_credentials_in_body: false,
        }
    }
}

impl<'a, R: WebRequest>RegistarRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    // fn code(&self) -> Option<Cow<str>> {
    //     self.body.unique_value("code")
    // }
    //
    // fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
    //     self.authorization.as_ref()
    //         .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    // }

    fn client_id(&self) -> Option<Cow<str>> {
        self.body.unique_value("client_id")
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.body.unique_value("redirect_uri")
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.body.unique_value("grant_type")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.body.unique_value(key)
    }

    fn allow_credentials_in_body(&self) -> bool {
        self.allow_credentials_in_body
    }
}

impl<E> From<Invalid> for FailParse<E> {
    fn from(_: Invalid) -> Self {
        FailParse::Invalid
    }
}
