//! Memory-safe multi-pattern scanner for AI Guardrails.
//!
//! Reads JSON lines on stdin:
//!   {"patterns": ["docker.sock", "/proc/", ...], "text": "..."}
//! Writes JSON lines on stdout:
//!   {"matched": true, "pattern": "docker.sock", "index": 12}
//!
//! Uses Aho-Corasick (linear in text length, no backtracking, no ReDoS,
//! no buffer overflows — Rust's memory safety guarantees apply).

use aho_corasick::{AhoCorasick, Match};
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{self, BufRead, Write};

#[derive(Deserialize)]
struct ScanRequest {
    patterns: Option<Vec<String>>,
    text: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    matched: bool,
    pattern: Option<String>,
    index: Option<usize>,
    count: usize,
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Rebuild the automaton per request (patterns can change per page policy).
    // For a hot deployment we could cache by pattern-set hash, but per-request
    // rebuild keeps it simple and correct.
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let req: ScanRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(
                    out,
                    "{{\"matched\":false,\"error\":\"invalid json: {}\"}}",
                    e
                );
                let _ = out.flush();
                continue;
            }
        };

        let patterns = req.patterns.unwrap_or_default();
        let text = req.text.unwrap_or_default();

        if patterns.is_empty() || text.is_empty() {
            let _ = writeln!(
                out,
                "{{\"matched\":false,\"pattern\":null,\"index\":null,\"count\":0}}"
            );
            let _ = out.flush();
            continue;
        }

        let ac = match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
        {
            Ok(a) => a,
            Err(e) => {
                let _ = writeln!(
                    out,
                    "{{\"matched\":false,\"error\":\"automaton build failed: {}\"}}",
                    e
                );
                let _ = out.flush();
                continue;
            }
        };

        let mut matches: Vec<Match> = ac.find_overlapping_iter(&text).collect();
        matches.sort_by_key(|m| m.start());

        if let Some(first) = matches.first() {
            let pat_index = first.pattern().as_usize();
            let pat = patterns.get(pat_index).cloned().unwrap_or_default();
            let _ = writeln!(
                out,
                "{{\"matched\":true,\"pattern\":{},\"index\":{},\"count\":{}}}",
                serde_json::to_string(&pat).unwrap(),
                first.start(),
                matches.len()
            );
        } else {
            let _ = writeln!(
                out,
                "{{\"matched\":false,\"pattern\":null,\"index\":null,\"count\":0}}"
            );
        }
        let _ = out.flush();
    }

    Ok(())
}
