use crate::sys::oauth_client_detail::{OauthClientRepository, Oauth2ClientDetail};
use crate::sys::oauth_client_detail::vo::{OauthClientDetailsVo, OauthClientDetailsQueryByPageVo};
use crate::sys::user::UserInfo;
use crate::db::Oauth2DataSource;
use async_trait::async_trait;
use crate::sys::role::vo::RoleVo;

#[async_trait]
impl OauthClientRepository for Oauth2DataSource {
    async fn find_oauth_client_details_by_id(id: String, salt: String) -> Result<OauthClientDetailsVo, Error> {
        unimplemented!()
    }

    async fn find_by_page(filters: OauthClientDetailsVo, salt: String) -> Result<OauthClientDetailsQueryByPageVo, Error> {
        unimplemented!()
    }

    async fn list(salt: String) -> Result<Vec<OauthClientDetailsVo>, Error> {
        unimplemented!()
    }

    async fn delete_oauth_client_details(id: String) -> Result<u64, Error> {
        unimplemented!()
    }

    async fn add(vo: OauthClientDetailsVo, current_user: UserInfo) -> Result<Oauth2ClientDetail, Error> {
        unimplemented!()
    }

    async fn find_by_roles(role_vos: Vec<RoleVo>, salt: String) -> Result<Vec<Oauth2ClientDetail>, Error> {
        unimplemented!()
    }

    async fn find_ids_by_role_id(role_id: String) -> Result<String, Error> {
        unimplemented!()
    }
}