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

/*
#[async_trait(?Send)]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;

    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>;
}

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


#[async_trait(?Send)]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;

    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>;
}

pub struct Oauth2ClientService{
    db: MysqlDataSource,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Standard Implementations of Registrars                            //
///////////////////////////////////////////////////////////////////////////////////////////////////

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(|| { Argon2::default() });

impl Oauth2ClientService {
    /// Create an empty map without any clients in it.
    pub async fn new() -> Self {
        Oauth2ClientService{
            db: MysqlDataSource::new().await,
            password_policy: None
        }
    }

    /// Insert or update the client record.
    pub async fn register_client(&mut self, client: Client) -> Result<String, RegistrarError>  {
        let password_policy = Self::current_policy(&self.password_policy);
        let encoded_client = client.encode(password_policy);
        match self.db.add_encoded_client(encoded_client).await{
            Ok(detail) => Ok(detail.client_id),
            Err(e) => Err(RegistrarError::Unspecified),
        }

    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy<'a>(policy: &'a Option<Box<dyn PasswordPolicy>>) -> &'a dyn PasswordPolicy {
        policy
            .as_ref().map(|boxed| &**boxed)
            .unwrap_or(&*DEFAULT_PASSWORD_POLICY)
    }
}

impl Extend<Client> for Oauth2ClientService {
    fn extend<I>(&mut self, iter: I) where I: IntoIterator<Item=Client> {
        iter.into_iter().for_each(|client| {
            smol::run(self.register_client(client));
        })
    }
}

impl FromIterator<Client> for Oauth2ClientService {
    fn from_iter<I>(iter: I) -> Self where I: IntoIterator<Item=Client> {
        let mut into = smol::run(Oauth2ClientService::new());
        into.extend(iter);
        into
    }
}


#[async_trait(?Send)]
impl<'s, R: Registrar + ?Sized> Registrar for &'s R {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        self.regist(client).await
    }
}

#[async_trait(?Send)]
impl<'s, R: Registrar + ?Sized> Registrar for &'s mut R {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>{
        (**self).regist(client).await
    }
}

#[async_trait(?Send)]
impl<R: Registrar + ?Sized> Registrar for Box<R> {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        (**self).regist(client).await
    }
}

#[async_trait(?Send)]
impl<R: Registrar + ?Sized> Registrar for Rc<R> {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        // (**self).regist(client)
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl<R: Registrar + ?Sized> Registrar for Arc<R> {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        // (**self).regist(client)
        unimplemented!()
    }
}

#[async_trait(?Send)]
impl<'s, R: Registrar + ?Sized + 's> Registrar for MutexGuard<'s, R> {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        (**self).regist(client).await
    }
}

#[async_trait(?Send)]
impl<'s, R: Registrar + ?Sized + 's> Registrar for RwLockWriteGuard<'s, R> {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound).await
    }

    async fn negotiate<'a>(&self, bound: BoundClient<'a>, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope).await
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase).await
    }

    async fn regist(&mut self,client: Client) -> Result<String, RegistrarError>{
        (**self).regist(client).await
    }
}


#[async_trait(?Send)]
impl Registrar for Oauth2ClientService {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {

        let client = match self.db.find_client_by_id(bound.client_id.as_ref()).await{
            Ok(None) => return Err(RegistrarError::Unspecified),
            Ok(Some(detail)) => detail,
            Err(e) => return Err(RegistrarError::Unspecified),
        };
        let redirect_uri = Url::parse(client.web_server_redirect_uri.unwrap().as_ref())
            .map_err(|e|RegistrarError::Unspecified)
            .unwrap();
        let additional_redirect_uris = vec![];
        // Perform exact matching as motivated in the rfc
        match bound.redirect_uri {
            None => (),
            Some(ref url) if url.as_ref().as_str() == redirect_uri.as_str() || additional_redirect_uris.contains(url) => (),
            _ => return Err(RegistrarError::Unspecified),
        }

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: bound.redirect_uri.unwrap_or_else(
                || Cow::Owned(redirect_uri.clone())),
        })
    }

    /// Always overrides the scope with a default scope.
    async fn negotiate<'a>(&self, bound: BoundClient<'a>, _scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        let client = self.db.find_client_by_id(&bound.client_id).await
            .map_err(|e| RegistrarError::Unspecified)
            .unwrap()
            .expect("Bound client appears to not have been constructed with this registrar");

        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: Scope::from_str(client.scope.unwrap().as_ref()).unwrap(),
        })
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        self.db.find_client_by_id(client_id).await
            .map_err(|e| RegistrarError::Unspecified)
            // .unwrap()
            .and_then(|op_client| -> Result<(), RegistrarError>{
                let client = op_client.unwrap();
                let encoded = match client.client_secret{
                    Some(passdata) => ClientType::Confidential { passdata: passdata.into_bytes() },
                    None => ClientType::Public
                };
                let encoded_client = EncodedClient{
                    client_id: client.client_id,
                    redirect_uri: Url::parse(client.web_server_redirect_uri.as_ref().unwrap()).unwrap(),
                    default_scope: Scope::from_str(client.scope.as_ref().unwrap()).unwrap(),
                    encoded_client: encoded
                };

                RegisteredClient::new(encoded_client.borrow(), password_policy)
                    .check_authentication(passphrase)
            })?;

        Ok(())
    }


    async fn regist(&mut self, client: Client) -> Result<String, RegistrarError>{
        println!(" in impl registar for ClientMap regist .");

        // let password_policy = Self::current_policy(&self.password_policy);
        // let encoded_client = client.encode(password_policy);

        // let client_id = encoded_client.client_id.clone();

        /* if self.clients.contains_key(&client_id){
             return Result::Err(RegistrarError::PrimitiveError);
         }*/
        // self.clients.insert(client_id.clone(), encoded_client);
        // self.register_client(client);
        self.register_client(client).await
    }
}
