pub use libbpf_cargo;
pub use libbpf_rs as libbpf;

mod obj;
pub use obj::OpenObject;

mod hashmap;
pub use hashmap::{HashMap, Pod};

mod prog;
pub use prog::Program;

#[cfg(feature = "tracing")]
pub mod tracing;

#[cfg(feature = "build")]
pub mod build;
pub use build::build;

// fn print(level: libbpf::PrintLevel, msg: String) {
//     let msg = msg.trim_start_matches("libbpf:").trim();

//     match level {
//         PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
//         PrintLevel::Info => info!(target: "libbpf", "{}", msg),
//         PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
//     }
// }
