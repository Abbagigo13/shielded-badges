use wasm_bindgen::prelude::*;

pub mod mul_demo;

#[wasm_bindgen]
pub fn hello() -> String {
    "ShieldedBadges circuit crate is alive".to_string()
}

#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}
