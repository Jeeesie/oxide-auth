pub mod redis;
pub mod vo;
#[cfg(feature = "with-mysql")]
pub mod my;
#[cfg(feature = "with-postgres")]
pub mod pg;

use serde::{Serialize, Deserialize};
use primitives::registrar::{Client, EncodedClient, ClientType};
use std::str::FromStr;
use std::borrow::Borrow;
use reqwest::Url;
use oauth_client_detail::vo::OauthClientDetailsVo;
use primitives::scope::Scope;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Oauth2ClientDetail{
    pub client_id: String,
    pub resource_ids: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub authorized_grant_types: Option<String>,
    pub web_server_redirect_uri: Option<String>,
    pub authorities: Option<String>,
    pub access_token_validity: Option<i32>,
    pub refresh_token_validity: Option<i32>,
    pub additional_information: Option<String>,
    pub autoapprove: Option<String>,
    pub custom_name: Option<String>,
}

impl Oauth2ClientDetail {
    pub fn from_encoded(encoded: EncodedClient) -> Self {
        let mut redirect_uris = encoded.redirect_uri.into_string();
        if !encoded.additional_redirect_uris.is_empty(){
            for uri in encoded.additional_redirect_uris{
                redirect_uris.push(',');
                redirect_uris.push_str(&uri.into_string())
            }
        }
        Oauth2ClientDetail{
            client_id: encoded.client_id,
            resource_ids: None,
            client_secret: match encoded.encoded_client{
                ClientType::Public => None,
                ClientType::Confidential {passdata} => Some(String::from_utf8(passdata).unwrap())
            },
            scope: Some(encoded.default_scope.to_string()),
            authorized_grant_types: Option::from("authorization_code".to_string()),
            web_server_redirect_uri: Option::from(redirect_uris),
            authorities: None,
            access_token_validity: Some(3600),
            refresh_token_validity:Some(3600),
            additional_information: None,
            autoapprove: None,
            custom_name: None,
        }
    }

    pub fn to_registrar_client(&self) -> Client {
        let scope = match Scope::from_str(&self.scope.as_ref().unwrap_or("default-scope".to_string().borrow())){
            Ok(s) => s,
            Err(e) => Scope { tokens: ["default-scope"].iter().map(|s| s.to_string()).collect() }
        };
        Client::confidential(
            &self.client_id,
            Url::parse(&self.web_server_redirect_uri.as_ref().unwrap_or("".to_string().borrow())).unwrap(),
            scope,
            (&self.client_secret.as_ref().unwrap()).as_ref(),
        )
    }

  /*  pub fn to_encoded_client(detail: Oauth2ClientDetail) -> EncodedClient {
        // let mut redirect_url= Ur;
        // let mut addtional_uris= vec![];
        // if let Some(uris) = &self.web_server_redirect_uri {
        //     let uris = uris.split(",").collect();
        //     for uri in uris {
        //         if redirect_url{
        //             redirect_url = Url::parse(uri)?
        //         }
        //         addtional_uris.push(Url::parse(uri))
        //     }
        // }

        let redirect_uri = Url::parse(detail.web_server_redirect_uri.unwrap().as_ref())?;
        EncodedClient{
            client_id: (detail.client_id).parse().unwrap(),
            redirect_uri,
            additional_redirect_uris: vec![],
            default_scope: Scope{ tokens: Default::default() },
            encoded_client: ClientType::Confidential
        }
    }*/
}

impl From<OauthClientDetailsVo> for Oauth2ClientDetail{
    fn from(vo: OauthClientDetailsVo) -> Self {
        Oauth2ClientDetail{
            client_id: vo.client_id,
            resource_ids: vo.resource_ids,
            client_secret: vo.client_secret,
            scope: Some(vo.scope.unwrap_or("default-scope".to_string())),
            authorized_grant_types: vo.authorized_grant_types,
            web_server_redirect_uri: Option::from(vo.callback_url),
            authorities: vo.authorities,
            access_token_validity: vo.access_token_validity,
            refresh_token_validity: vo.refresh_token_validity,
            additional_information: vo.additional_information,
            autoapprove: vo.autoapprove,
            custom_name: vo.custom_name,
        }
    }

}

pub trait OauthClientRedisRepository {

    fn list(&self, salt: String) -> anyhow::Result<Vec<Oauth2ClientDetail>>;

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<Oauth2ClientDetail>;

    fn regist_from_encoded_client(&self, client: EncodedClient)  -> anyhow::Result<()>;

    fn regist_from_detail(&self, detail: & Oauth2ClientDetail)  -> anyhow::Result<()>;

}

/*
#[cfg(test)]
mod tests {

    use primitives::redis::RedisDataSource;
    use oauth_client_detail::OauthClientRedisRepository;

    #[tokio::test]
    fn test_find_client_by_id(){
        let conn = RedisDataSource::new();
        let ans = conn.find_client_by_id("addb");
        println!("{:?}", ans);

    }

}*/