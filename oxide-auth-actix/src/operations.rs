use crate::{OAuthRequest, OAuthResponse, OAuthOperation, WebError};
use oxide_auth::{
    endpoint::{AccessTokenFlow, AuthorizationFlow, Endpoint, RefreshFlow, ResourceFlow},
    primitives::grant::Grant,
};
use oxide_auth::primitives::registrar::Client;
use oxide_auth_async::endpoint::registration::RegisterFlow;

/// Authorization-related operations
pub struct Authorize(pub OAuthRequest);

impl OAuthOperation for Authorize {
    type Item = OAuthResponse;
    type Error = WebError;

    fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest>,
        WebError: From<E::Error>,
    {
        AuthorizationFlow::prepare(endpoint)?
            .execute(self.0)
            .map_err(WebError::from)
    }
}

/// Token-related operations
pub struct Token(pub OAuthRequest);

impl OAuthOperation for Token {
    type Item = OAuthResponse;
    type Error = WebError;

    fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest>,
        WebError: From<E::Error>,
    {
        AccessTokenFlow::prepare(endpoint)?
            .execute(self.0)
            .map_err(WebError::from)
    }
}

/// Refresh-related operations
pub struct Refresh(pub OAuthRequest);

impl OAuthOperation for Refresh {
    type Item = OAuthResponse;
    type Error = WebError;

    fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest>,
        WebError: From<E::Error>,
    {
        RefreshFlow::prepare(endpoint)?
            .execute(self.0)
            .map_err(WebError::from)
    }
}

/// Resource-related operations
pub struct Resource(pub OAuthRequest);

impl OAuthOperation for Resource {
    type Item = Grant;
    type Error = Result<OAuthResponse, WebError>;

    fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest>,
        WebError: From<E::Error>,
    {
        ResourceFlow::prepare(endpoint)
            .map_err(|e| Err(WebError::from(e)))?
            .execute(self.0)
            .map_err(|r| r.map_err(WebError::from))
    }
}

/// Client related operations
pub struct ClientRegistar(pub OAuthRequest);

impl OAuthOperation for ClientRegistar {
    type Item = OAuthResponse;
    type Error = WebError;

    fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error> where
        E: Endpoint<OAuthRequest>,
        WebError: From<E::Error> {
        // if endpoint.registrar().is_none() {
        //     return Err(endpoint.error(OAuthError::PrimitiveError));
        // }
        // let private_id = "PublicClientId";
        // let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";
        // let client_url = "localhost:8080/ssologin";
        //
        // let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
        //                                           "default".parse().unwrap(), private_passphrase);
        // endpoint.registrar().unwrap().regist(private_client);
        // // simple_test_suite(&mut registar, Registrar::regist);
        // Ok(OAuthResponse::ok())
        let r = self.0;
        let tmp = RegisterFlow::prepare(endpoint)?;
        let tmp1 = smol::run(tmp.execute(r));
        tmp1.map_err(WebError::from)
    }
}