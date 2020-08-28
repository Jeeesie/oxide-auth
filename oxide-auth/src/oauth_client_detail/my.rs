use crate::sys::oauth_client_detail::{OauthClientRepository, Oauth2ClientDetail};
use crate::sys::oauth_client_detail::vo::{OauthClientDetailsVo, OauthClientDetailsQueryByPageVo};
use async_trait::async_trait;
use crate::sys::role::vo::RoleVo;
use crate::db::{Oauth2DataSource};
use sqlx_core::error::Error;
use oxide_auth::primitives::registrar_b::{EncodedClient, ClientType};

#[async_trait]
impl OauthClientRepository for Oauth2DataSource {

    async fn find_by_grant_type(&self, grant_type: String) -> Result<Vec<Oauth2ClientDetail>, Error> {
        match sqlx::query_as!(
        Oauth2ClientDetail,
        r#"select * from oauth_client_details where client_id is not null and authorized_grant_types like ? "#,
        grant_type
        ).fetch_all(&self.pool).await {
            Ok(r) => Ok(r),
            Err(e) => Err(e)
        }
    }

    async fn find_by_page(&self, filters: OauthClientDetailsVo, salt: String) -> anyhow::Result<OauthClientDetailsQueryByPageVo> {
        unimplemented!()
    }

    async fn list(&self, salt: String) -> anyhow::Result<Vec<OauthClientDetailsVo>> {
        unimplemented!()
    }

    async fn delete_oauth_client_details(&self, id: String) -> anyhow::Result<u64> {
        unimplemented!()
    }

    async fn add(&self, vo: OauthClientDetailsVo) -> anyhow::Result<Oauth2ClientDetail> {
        match sqlx::query!(
        r#"INSERT INTO oauth_client_details
        (client_id, resource_ids, client_secret, scope, authorized_grant_types,
        web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity,
        additional_information, autoapprove, custom_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?)"#
        , &vo.client_id,
        &vo.resource_ids,
        &vo.client_secret,
        &vo.scope,
        &vo.authorized_grant_types,
        &vo.callback_url,
        &vo.authorities,
        &vo.access_token_validity.unwrap_or(3600),
        &vo.refresh_token_validity.unwrap_or(3600),
        &vo.additional_information,
        &vo.autoapprove,
        &vo.custom_name
        ).execute(&self.pool).await{
            Ok(c) => {
                let r = sqlx::query_as!(Oauth2ClientDetail, r#"select * from oauth_client_details where client_id = ?"#, &vo.client_id).fetch_one(&self.pool).await?;
                Ok(r)
            },
            Err(e) => Err(anyhow!("{:?}", e))
        }
    }


    async fn add_encoded_client(&self, ec:EncodedClient) -> anyhow::Result<Oauth2ClientDetail>{
        let secret = match ec.encoded_client{
            ClientType::Confidential {passdata} => passdata,
            ClientType::Public => "".to_string().into_bytes()
        };
        match sqlx::query!(
        r#"INSERT INTO oauth_client_details
        (client_id, client_secret, scope, authorized_grant_types,
        web_server_redirect_uri, access_token_validity, refresh_token_validity,
        autoapprove, custom_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#
        , &ec.client_id,
        secret,
        &ec.default_scope.to_string(),
        "authorization_code",
        &ec.redirect_uri.as_str(),
        3600,
        3600,
        1,
        &ec.client_id,
        ).execute(&self.pool).await{
            Ok(c) => {
                let r = sqlx::query_as!(Oauth2ClientDetail, r#"select * from oauth_client_details where client_id = ?"#, &ec.client_id).fetch_one(&self.pool).await?;
                Ok(r)
            },
            Err(e) => Err(anyhow!("{:?}", e))
        }
    }


    async fn find_client_by_id(&self, id: &str) -> anyhow::Result<Option<Oauth2ClientDetail>>{
        let r = sqlx::query_as!(
            Oauth2ClientDetail,
            r#"select * from oauth_client_details where client_id = ?"#,
            id
            ).fetch_optional(&self.pool).await?;
        Ok(r)
    }


    async fn find_by_roles(&self, role_vos: Vec<RoleVo>, salt: String) -> anyhow::Result<Vec<Oauth2ClientDetail>> {
        unimplemented!()
    }

    async fn find_ids_by_role_id(&self, role_id: String) -> anyhow::Result<String> {
        unimplemented!()
    }
}