use dotenv::dotenv;
use r2d2::Pool;
use r2d2_redis::RedisConnectionManager;
use std::env;

pub const REDIS_POOL_SIZE: u32 = 32;

#[derive(Debug, Clone)]
pub struct RedisDataSource {
    pub url: String,
    pub pool: Pool<RedisConnectionManager>,
}

impl Default for RedisDataSource {
    fn default() -> Self {
        Self::new()
    }
}


impl RedisDataSource {

    pub fn new() -> Self {
        dotenv().ok();
        let url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let pool = REDIS_POOL.clone();
        RedisDataSource { url, pool }
    }

    pub fn get_url(&self) -> String {
        self.url.to_string()
    }
    pub fn get_pool(self) -> Pool<RedisConnectionManager> {
        self.pool
    }
}


lazy_static! {
    pub static ref REDIS_POOL: r2d2::Pool<r2d2_redis::RedisConnectionManager> = {
        dotenv::dotenv().ok();
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
        let manager = r2d2_redis::RedisConnectionManager::new(redis_url).unwrap();
        let max_pool_size: u32 = env::var("REDIS_POOL_SIZE")
            .unwrap_or_else(|_| REDIS_POOL_SIZE.to_string())
            .parse::<u32>()
            .unwrap_or(REDIS_POOL_SIZE);

        r2d2::Pool::builder()
            .max_size(max_pool_size)
            .build(manager)
            .expect("Failed to create redis pool.")
    };

    // Used to update core data into redis master, such as person, role and dept etc.
    // pub static ref MASTER_REDIS_POOL: Pool<r2d2_redis::RedisConnectionManager> = {
    //     dotenv().ok();
    //     let redis_url = env::var("MASTER_REDIS_URL").expect("MASTER_REDIS_URL must be set");
    //     let manager = r2d2_redis::RedisConnectionManager::new(redis_url).unwrap();
    //     r2d2::Pool::builder()
    //         .max_size(REDIS_POOL_SIZE)
    //         .build(manager)
    //         .expect("Failed to create master redis pool.")
    // };

}
