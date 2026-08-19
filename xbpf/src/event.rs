use crate::map::FromRecord;
use std::{error::Error, fmt};

use tracing::Level;

// TODO: this currently has two definitions. Make sure there's only one.
const BPF_TRACING_STR_LEN: usize = 128;
const EVENT_BASE_SIZE: usize = 4 + BPF_TRACING_STR_LEN;
const EVENT_WITH_FILE_SIZE: usize = EVENT_BASE_SIZE + BPF_TRACING_STR_LEN + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventDecodeError {
    BufferTooShort { expected: usize, actual: usize },
    InvalidLevel(u8),
    InvalidKind(u8),
    InvalidUtf8(&'static str),
}

impl fmt::Display for EventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventDecodeError::BufferTooShort { expected, actual } => write!(
                f,
                "event buffer too short (expected at least {expected} bytes, got {actual})",
            ),
            EventDecodeError::InvalidLevel(level) => {
                write!(f, "invalid log level: {level}")
            }
            EventDecodeError::InvalidKind(kind) => write!(f, "invalid event kind: {kind}"),
            EventDecodeError::InvalidUtf8(field) => {
                write!(f, "invalid UTF-8 in {field} field")
            }
        }
    }
}

impl Error for EventDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    Message(Level),
    StartSpan(Level),
    EndSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event {
    pub kind: Kind,
    pub content: String,
    pub cpu: usize,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl TryFrom<&[u8]> for Event {
    type Error = EventDecodeError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < EVENT_BASE_SIZE {
            return Err(EventDecodeError::BufferTooShort {
                expected: EVENT_BASE_SIZE,
                actual: buf.len(),
            });
        }

        let level_raw = buf[0];
        let kind_raw = buf[1];
        let cpu = u16::from_ne_bytes([buf[2], buf[3]]) as usize;

        let msg_start = 4;
        let msg_end = msg_start + BPF_TRACING_STR_LEN;
        let msg = parse_cstr(&buf[msg_start..msg_end], "msg")?;

        let has_file = buf.len() >= EVENT_WITH_FILE_SIZE;
        if cfg!(feature = "tracing-source-loc") && !has_file {
            return Err(EventDecodeError::BufferTooShort {
                expected: EVENT_WITH_FILE_SIZE,
                actual: buf.len(),
            });
        }

        let (file, line) = if has_file {
            let file_start = msg_end;
            let file_end = file_start + BPF_TRACING_STR_LEN;
            let file = parse_cstr(&buf[file_start..file_end], "file")?;

            let line_start = file_end;
            let line_bytes: [u8; 4] = buf[line_start..line_start + 4]
                .try_into()
                .expect("line bytes length verified");
            let line = u32::from_ne_bytes(line_bytes);

            let file = if file.is_empty() { None } else { Some(file) };
            (file, Some(line))
        } else {
            (None, None)
        };

        let kind = match kind_raw {
            0 => Kind::Message(parse_level(level_raw)?),
            1 => Kind::StartSpan(parse_level(level_raw)?),
            2 => Kind::EndSpan,
            other => return Err(EventDecodeError::InvalidKind(other)),
        };

        Ok(Event {
            kind,
            content: msg,
            cpu,
            file,
            line,
        })
    }
}

impl FromRecord for Event {
    type Error = EventDecodeError;

    fn from_record(record: &[u8]) -> Result<Self, Self::Error> {
        Event::try_from(record)
    }
}

fn parse_level(level: u8) -> Result<Level, EventDecodeError> {
    match level {
        1 => Ok(Level::ERROR),
        2 => Ok(Level::WARN),
        3 => Ok(Level::INFO),
        4 => Ok(Level::DEBUG),
        5 => Ok(Level::TRACE),
        other => Err(EventDecodeError::InvalidLevel(other)),
    }
}

fn parse_cstr(bytes: &[u8], field: &'static str) -> Result<String, EventDecodeError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(|s| s.to_string())
        .map_err(|_| EventDecodeError::InvalidUtf8(field))
}

pub type CallsiteKey = (Option<String>, Option<u32>, bool, tracing::metadata::Level);

impl TryFrom<Event> for CallsiteKey {
    type Error = ();
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        match event.kind {
            Kind::StartSpan(level) => Ok((event.file.clone(), event.line, true, level)),
            Kind::EndSpan => Err(()),
            Kind::Message(level) => Ok((event.file.clone(), event.line, false, level)),
        }
    }
}
