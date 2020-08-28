use oauth_client_detail::{OauthClientRedisRepository, Oauth2ClientDetail};
use primitives::redis::RedisDataSource;
use std::collections::HashMap;
use r2d2_redis::redis::{Commands, RedisError};
use serde_json::Error;
use primitives::registrar::EncodedClient;

impl OauthClientRedisRepository for RedisDataSource{
    fn list(&self, salt: String) -> anyhow::Result<Vec<Oauth2ClientDetail>> {
        unimplemented!()
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<Oauth2ClientDetail> {
        let mut r = self.pool.get().unwrap();
        let client_str = r.get::<&str, String>(id)?;
        Ok(serde_json::from_str::<Oauth2ClientDetail>(&client_str)?)
    }

    /// 一般不用这个方法，因为EncodedClient里缺少很多信息，比如：scope只能用default-scope
    fn regist_from_encoded_client(&self, client: EncodedClient)  -> anyhow::Result<()>{
        let mut pool = self.pool.get().unwrap();
        let detail = Oauth2ClientDetail::from_encoded(client);
        let client_str = serde_json::to_string(&detail)?;
        println!("add..");
        pool.set(&detail.client_id, client_str)?;
        Ok(())
    }

    fn regist_from_detail(&self, detail: &Oauth2ClientDetail)  -> anyhow::Result<()>{
        let mut pool = self.pool.get().unwrap();
        let client_str = serde_json::to_string(&detail)?;
        println!("add..");
        pool.set(&detail.client_id, client_str)?;
        Ok(())
    }
}

