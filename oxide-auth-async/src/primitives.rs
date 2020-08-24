//! Async versions of all primitives traits.
use async_trait::async_trait;
use oxide_auth::primitives::{authorizer, issuer, registrar, grant::Grant, scope::Scope};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken};
use oxide_auth::primitives::registrar::{Client, ClientUrl, BoundClient, RegistrarError, PreGrant};

#[async_trait(?Send)]
pub trait Authorizer {
    async fn authorize(&mut self, _: Grant) -> Result<String, ()>;

    async fn extract(&mut self, _: &str) -> Result<Option<Grant>, ()>;
}

#[async_trait(?Send)]
impl<T> Authorizer for T
where
    T: authorizer::Authorizer + ?Sized,
{
    async fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        authorizer::Authorizer::authorize(self, grant)
    }

    async fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        authorizer::Authorizer::extract(self, token)
    }
}

#[async_trait(?Send)]
pub trait Issuer {
    async fn issue(&mut self, _: Grant) -> Result<IssuedToken, ()>;

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()>;

    async fn recover_token(&mut self, _: &str) -> Result<Option<Grant>, ()>;

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()>;
}

#[async_trait(?Send)]
impl<T> Issuer for T
where
    T: issuer::Issuer + ?Sized,
{
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        issuer::Issuer::issue(self, grant)
    }

    async fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        issuer::Issuer::refresh(self, token, grant)
    }

    async fn recover_token(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        issuer::Issuer::recover_token(self, token)
    }

    async fn recover_refresh(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        issuer::Issuer::recover_refresh(self, token)
    }
}

#[async_trait(?Send)]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;

    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>;
}
/*
#[async_trait(?Send)]
impl<T> Registrar for T
where
    T: registrar::Registrar + ?Sized,
{
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        registrar::Registrar::bound_redirect(self, bound)
    }

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        registrar::Registrar::negotiate(self, client, scope)
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        registrar::Registrar::check(self, client_id, passphrase)
    }

    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>{
        registrar::Registrar::regist(self, client)
    }
}*/

