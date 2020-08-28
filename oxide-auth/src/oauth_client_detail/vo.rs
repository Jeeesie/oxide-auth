use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct OauthClientDetailsVo{
    pub client_id: String,
    pub resource_ids: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub authorized_grant_types: Option<String>,
    pub callback_url: String,
    pub authorities: Option<String>,
    pub access_token_validity: Option<i32>,
    pub refresh_token_validity: Option<i32>,
    pub additional_information: Option<String>,
    pub autoapprove: Option<String>,
    pub custom_name: Option<String>,
}
/*
impl From<Oauth2ClientDetail> for OauthClientDetailsVo{
    fn from(c: Oauth2ClientDetail) -> Self {
        OauthClientDetailsVo{
            client_id: c.client_id,
            resource_ids: c.resource_ids,
            client_secret: c.client_secret,
            scope: c.scope,
            authorized_grant_types: Option::from(c.authorized_grant_types),
            callback_url: c.web_server_redirect_uri,
            authorities: c.authorities,
            access_token_validity: c.access_token_validity.u,
            refresh_token_validity: c.refresh_token_validity,
            additional_information: c.additional_information,
            autoapprove: c.autoapprove,
            custom_name: c.custom_name,
        }
    }
}*/

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct OauthClientDetailsQueryByPageVo{

}