//! Rich and event-based diagnostic information for eBPF.
//!
//! It exports a set of macros that can be used to emit
//! diagnostic events from eBPF programs. The events are
//! efficiently copied to user space via a ring buffer
//! and integrated into the [`tracing`] infrastructure.
//!
//! # Example
//!
//! ```no_run
//! # use std::mem::MaybeUninit;
//! # use xbpf::libbpf;
//! # mod tracing_subscriber {
//! #     pub struct Fmt;
//! #     pub struct EnvFilter;
//! #
//! #     pub fn fmt() -> Fmt {
//! #         Fmt
//! #     }
//! #
//! #     impl EnvFilter {
//! #         pub fn from_default_env() -> Self {
//! #             EnvFilter
//! #         }
//! #     }
//! #
//! #     impl Fmt {
//! #         pub fn with_env_filter(self, _filter: EnvFilter) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn with_file(self, _with_file: bool) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn with_line_number(self, _with_line_number: bool) -> Self {
//! #             self
//! #         }
//! #
//! #         pub fn init(self) {}
//! #     }
//! # }
//! # struct SkelBuilder;
//! # struct OpenSkel;
//! # struct Skel;
//! #
//! # impl Default for SkelBuilder {
//! #     fn default() -> Self {
//! #         Self
//! #     }
//! # }
//! #
//! # impl SkelBuilder {
//! #     fn open(&self, _open_obj: &mut MaybeUninit<()>) -> libbpf::Result<OpenSkel> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl OpenSkel {
//! #     fn load(self) -> libbpf::Result<Skel> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # impl Skel {
//! #     fn object(&self) -> &libbpf::Object {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # fn main() -> libbpf::Result<()> {
//!
//! tracing_subscriber::fmt()
//!     .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
//!     .with_file(true)
//!     .with_line_number(true)
//!     .init();
//!
//! let mut open_obj = MaybeUninit::uninit();
//! let skel_builder = SkelBuilder::default();
//! let open_skel = skel_builder.open(&mut open_obj)?;
//! let skel = open_skel.load()?;
//!
//! xbpf::tracing::try_init(skel.object());
//! # Ok(())
//! # }
//! ```
//!
//! And in your eBPF program:
//!
//! ```custom,{.language-c}
//! bpf_info("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
//! ```
//!
//! [`tracing`]: https://github.com/tokio-rs/tracing
use crate::{
    event::{CallsiteKey, Event, Kind},
    libbpf::{self, MapCore, MapHandle, PrintLevel},
    map::RingBuf,
};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    path::{Component, Path, PathBuf},
    thread::{self},
};
use tracing::{self, metadata::Metadata, span::EnteredSpan};

const TARGET: &str = "bpf";

/// How many events are buffered in user space before they are dropped. The
/// events are small, so this is generous enough to absorb a burst that the
/// eBPF ring buffer cannot hold on its own.
const USERSPACE_CAPACITY: usize = 16 * 1024;

type Spans = Vec<VecDeque<(String, EnteredSpan)>>;

thread_local! {
    static CALLSITES: RefCell<HashMap<CallsiteKey, &'static Metadata<'static>>> = RefCell::new(HashMap::new());
    static SPANS: RefCell<Spans> = {
        let cpus = thread::available_parallelism().unwrap().get();
        let mut spans: Spans = Vec::new();
        for _ in 0..cpus {
            spans.push(VecDeque::new());
        }
        RefCell::new(spans)
    };
}

/// Callback for libbpf to print messages to the tracing infrastructure.
fn print(level: libbpf::PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => tracing::debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => tracing::info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => tracing::warn!(target: "libbpf", "{}", msg),
    }
}

/// Initializes a ring buffer reader that continuously observes and
/// emits tracing events.
///
/// # Errors
/// Returns an Error if the `trace_pipe` file cannot be opened
/// or found.
pub fn try_init(obj: &libbpf::Object) -> libbpf::Result<()> {
    if libbpf::get_print().is_none() {
        libbpf::set_print(Some((PrintLevel::Debug, print)));
    }

    let mut events: Option<MapHandle> = None;

    for map in obj.maps() {
        if map.name().eq("bpf_tracing_events") {
            let map_id = map.info()?.info.id;
            events = Some(MapHandle::from_map_id(map_id)?);
        }
    }

    let Some(events) = events else {
        return Err(libbpf::Error::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "event ring buffer not found",
        )));
    };

    let mut ring_buf: RingBuf<Event> = RingBuf::new(events, USERSPACE_CAPACITY)?;

    // A single long lived thread, so that the per CPU span stacks and the
    // callsite cache, which are thread local, stay consistent across events.
    thread::spawn(move || {
        while let Some(event) = ring_buf.blocking_recv() {
            match event {
                Ok(event) => emit(event),
                Err(err) => tracing::warn!(target: TARGET, "Failed to decode event: {err}"),
            }
        }
    });

    Ok(())
}

fn strip_matching_prefix_components(full: &Path, base: &Path) -> PathBuf {
    let mut full_it = full.components().peekable();
    let mut base_it = base.components().peekable();

    while let (Some(f), Some(b)) = (full_it.peek(), base_it.peek()) {
        if f == b {
            full_it.next();
            base_it.next();
        } else {
            break;
        }
    }

    let mut out = PathBuf::new();
    for c in full_it {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => out.push("."),
            Component::ParentDir => out.push(".."),
            Component::RootDir => out.push(Path::new("/")),
            Component::Prefix(p) => out.push(p.as_os_str()),
        }
    }
    out
}

fn get_callsite(key: CallsiteKey) -> &'static Metadata<'static> {
    CALLSITES.with_borrow_mut(|cs| {
        if let Some(meta) = cs.get(&key) {
            *meta
        } else {
            let (file, line, is_span, level) = key;

            let callsite = if is_span {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[])
            } else {
                tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::SPAN, fields: &[])
            };

            let static_file: Option<&'static str> = if let Some(ref file) = file {
                let path = Path::new(&file);
                let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
                let rel = strip_matching_prefix_components(path, manifest)
                    .to_string_lossy()
                    .to_string();

                Some(Box::leak(rel.into_boxed_str()) as &'static str)
            } else {
                None
            };

            let meta = Box::leak(Box::new(Metadata::new(
                "",
                TARGET,
                level,
                static_file,
                line,
                None,
                tracing::field::FieldSet::new(
                    &["message"],
                    tracing::callsite::Identifier(callsite),
                ),
                if is_span {
                    tracing::metadata::Kind::SPAN
                } else {
                    tracing::metadata::Kind::EVENT
                },
            )));

            let key = (file, line, is_span, level);
            cs.insert(key, meta);

            let meta: &'static Metadata = meta;
            meta
        }
    })
}

fn emit(event: Event) {
    let cpu = event.cpu;
    SPANS.with_borrow_mut(|spans| {
        // `available_parallelism` only counts the CPUs this process may run on,
        // which can be fewer than the ids the kernel reports events from.
        if cpu >= spans.len() {
            spans.resize_with(cpu + 1, VecDeque::new);
        }

        match &event.kind {
            Kind::Message(lvl) => {
                if *lvl <= tracing::metadata::LevelFilter::current() {
                    let content = event.content.clone();
                    let meta = get_callsite(event.try_into().unwrap());
                    let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                    tracing::Event::child_of(
                        parent,
                        meta,
                        &tracing::valueset_all!(meta.fields(), "{}", content),
                    );
                }
            }
            Kind::StartSpan(lvl) => {
                if *lvl <= tracing::metadata::LevelFilter::current() {
                    let content = event.content.clone();
                    let meta = get_callsite(event.try_into().unwrap());
                    let parent = spans[cpu].back().and_then(|(_, p)| p.id());

                    let span = tracing::Span::child_of(
                        parent,
                        meta,
                        &tracing::valueset_all!(meta.fields(), "{}", content),
                    );
                    spans[cpu].push_back((content, span.entered()));
                }
            }
            Kind::EndSpan => {
                let content = event.content;
                while let Some((n, _)) = spans[cpu].pop_back() {
                    if n == content {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use super::*;

    #[test]
    fn leaks_one_callsite_per_level_and_kind() {
        fn callsite_len() -> usize {
            CALLSITES.with_borrow(|cs| cs.len())
        }

        let event_msg_info1 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 1".to_string(),
            cpu: 1,
            file: None,
            line: None,
        };

        let event_msg_info2 = Event {
            kind: Kind::Message(Level::INFO),
            content: "event 2".to_string(),
            cpu: 9,
            file: None,
            line: None,
        };

        let _callsite1 = get_callsite(event_msg_info1.try_into().unwrap());
        let _callsite2 = get_callsite(event_msg_info2.try_into().unwrap());
        assert_eq!(callsite_len(), 1);

        let event_span_info3 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 3".to_string(),
            cpu: 29,
            file: None,
            line: None,
        };
        let _callsite3 = get_callsite(event_span_info3.try_into().unwrap());
        assert_eq!(callsite_len(), 2);

        let event_span_info4 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 4".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
        };
        let _callsite4 = get_callsite(event_span_info4.try_into().unwrap());
        assert_eq!(callsite_len(), 3);

        let event_span_info5 = Event {
            kind: Kind::StartSpan(Level::INFO),
            content: "event 5".to_string(),
            cpu: 29,
            file: Some(String::from("this/is/a/test_file.rs")),
            line: Some(12),
        };
        let _callsite5 = get_callsite(event_span_info5.try_into().unwrap());
        assert_eq!(callsite_len(), 3);
    }
}
