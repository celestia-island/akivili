use anyhow::Result;
use std::io::{self, Read, Write};

use akivili_iepl::IeplEngine;

fn main() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let engine = IeplEngine::new();
    match engine.transpile(&input) {
        Ok(result) => {
            io::stdout().write_all(result.js_code.as_bytes())?;
            Ok(())
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
