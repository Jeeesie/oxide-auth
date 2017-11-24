use super::frontend::*;
use super::backend::{CodeRef, ErrorUrl, IssuerRef};
use super::authorizer::Storage;
use super::issuer::TokenMap;
use super::registrar::ClientMap;
use std::collections::HashMap;
use url::Url;

struct CraftedRequest {
    query: Option<HashMap<String, Vec<String>>>,
    urlbody: Option<HashMap<String, Vec<String>>>,
}

enum CraftedResponse {
    Redirect(Url),
    Text(String),
    Json(String),
    RedirectFromError(Url),
    ClientError(Box<CraftedResponse>),
    Unauthorized(Box<CraftedResponse>),
    Authorization(Box<CraftedResponse>, String),
}

impl WebRequest for CraftedRequest {
    type Response = CraftedResponse;

    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()> {
        self.query.clone().ok_or(())
    }

    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()> {
        self.urlbody.as_ref().ok_or(())
    }
}

impl WebResponse for CraftedResponse {
    fn redirect(url: Url) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Redirect(url))
    }

    fn text(text: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Text(text.to_string()))
    }

    fn json(data: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Json(data.to_string()))
    }

    fn redirect_error(target: ErrorUrl) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::RedirectFromError(target.into()))
    }

    fn as_client_error(self) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::ClientError(self.into()))
    }

    fn as_unauthorized(self) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Unauthorized(self.into()))
    }

    fn with_authorization(self, kind: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Authorization(self.into(), kind.to_string()))
    }
}

struct TestGenerator(String);

impl super::TokenGenerator for TestGenerator {
    fn generate(&self, _grant: &super::Grant) -> String {
        self.0.clone()
    }
}

struct Allow(String);

impl OwnerAuthorizer for Allow {
    type Request = CraftedRequest;
    fn get_owner_authorization(&self, _: &mut CraftedRequest, _: AuthenticationRequest)
    -> Result<(Authentication, CraftedResponse), OAuthError> {
        Ok((Authentication::Authenticated(self.0.clone()), CraftedResponse::Text("".to_string())))
    }
}

#[test]
fn authorize_and_get() {
    let mut registrar = ClientMap::new();
    let mut authorizer = Storage::new(TestGenerator("AuthToken".to_string()));
    let mut issuer = TokenMap::new(TestGenerator("AcessToken".to_string()));

    let client_id = "ClientId";
    let owner_id = "Owner";
    let redirect_url = "https://client.example/endpoint";

    registrar.register_client(client_id, Url::parse(redirect_url).unwrap());

    let mut authrequest = CraftedRequest {
        query: Some(vec![("client_id", client_id),
                         ("redirect_url", redirect_url),
                         ("response_type", "code")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect()),
        urlbody: Some(HashMap::new()),
    };

    let prepared = AuthorizationFlow::prepare(&mut authrequest).expect("Failure during authorization preparation");
    let pagehandler = Allow(owner_id.to_string());
    match AuthorizationFlow::handle(CodeRef::with(&mut registrar, &mut authorizer), prepared, &pagehandler)
          .expect("Failure during authorization handling") {
        CraftedResponse::Redirect(ref url) if url.as_str() == "https://client.example/endpoint?code=AuthToken"
            => (),
        _ => panic!()
    };

    let mut tokenrequest = CraftedRequest {
        query: Some(HashMap::new()),
        urlbody: Some(vec![("client_id", client_id),
                           ("redirect_url", redirect_url),
                           ("code", "AuthToken"),
                           ("grant_type", "authorization_code")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect()),
    };

    let prepared = GrantFlow::prepare(&mut tokenrequest).expect("Failure during access token preparation");
    match GrantFlow::handle(IssuerRef::with(&mut authorizer, &mut issuer), prepared)
          .expect("Failure during access token handling") {
        CraftedResponse::Json(_) // TODO check json data for correct return value
            => (),
        _ => panic!(),
    }

}
