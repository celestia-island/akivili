//! Thin shell for [`akivili_registry::cli`]; all logic lives in the
//! library so tests exercise it without spawning processes.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = akivili_registry::cli::run(&args);
    std::process::exit(code);
}
