pub mod program;
pub mod proofs;

pub use common::sudoku;
pub use secp;

pub mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}
