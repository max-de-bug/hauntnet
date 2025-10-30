use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub ghost_name: String,
}

pub fn load_config() -> Config {
    let path = "./.hauntnet_config.json";
    if let Ok(data) = fs::read_to_string(path) {
        serde_json::from_str(&data).unwrap_or(Config {
            ghost_name: "shadow_wraith".to_string(),
        })
    } else {
        Config {
            ghost_name: "shadow_wraith".to_string(),
        }
    }
}
