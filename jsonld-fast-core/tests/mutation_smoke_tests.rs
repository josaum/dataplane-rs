// Rust guideline compliant 2026-02-21
//! Mutation smoke: malformed bytes into every public entry point.
//!
//! The W3C fixtures and a few YAML-LD seeds are mutated with a fixed-seed
//! generator (byte flips, truncation, token insertion, range duplication)
//! and fed to every public entry point on a 256 KiB thread, under a global
//! allocator that aborts once live memory passes 1 GiB. A panic fails the
//! test; a stack overflow or an allocation-cap trip aborts the binary.
//! Adapted from `parsers-rs/tools/mutation_smoke.rs`; deterministic, no
//! clock.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use jsonld_fast_core::{
    JsonLdLimits, JsonLdOptions, YamlLdOptions, YamlLdProfile, compact, compact_streaming, expand,
    expand_streaming, expand_streaming_graph, frame, from_quads, from_quads_streaming,
    parse_document, parse_streaming_graph, parse_yaml_ld_bytes, to_quads, to_quads_streaming,
    to_yaml_ld, validate_streaming_form, write_streaming_document,
};
use serde_json::{Value, json};

/// Most memory the test binary may hold live before it aborts: 1 GiB.
const ALLOCATION_CAP_BYTES: usize = 1 << 30;

/// Stack of the thread the entry points run on.
const SMALL_STACK_BYTES: usize = 256 * 1024;

/// Mutated inputs per seed family; fixed so failures reproduce.
const ITERATIONS: usize = 1_500;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static REPORTING_CAP: AtomicBool = AtomicBool::new(false);

/// Aborts the process once live heap memory passes [`ALLOCATION_CAP_BYTES`].
struct CappedAllocator;

impl CappedAllocator {
    fn charge(size: usize) {
        let live = LIVE_BYTES
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        if live > ALLOCATION_CAP_BYTES && !REPORTING_CAP.swap(true, Ordering::SeqCst) {
            // Writing may allocate; the flag lets that through. A failed
            // write cannot be reported anyway, and `abort` follows.
            let _ignored = writeln!(
                std::io::stderr(),
                "mutation_smoke: allocation cap exceeded ({size} byte request, {live} bytes live)"
            );
            std::process::abort();
        }
    }
}

// SAFETY: every method forwards to `System` with the caller's unchanged
// pointer and layout; the only added behavior is byte accounting and abort.
unsafe impl GlobalAlloc for CappedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::charge(layout.size());
        // SAFETY: forwarding the unchanged layout to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::charge(layout.size());
        // SAFETY: forwarding the unchanged layout to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `pointer` came from this allocator with this layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            Self::charge(new_size.saturating_sub(layout.size()));
        } else {
            LIVE_BYTES.fetch_sub(layout.size().saturating_sub(new_size), Ordering::Relaxed);
        }
        // SAFETY: forwarding the original pointer, layout, and new size to
        // the system allocator that created the allocation.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CappedAllocator = CappedAllocator;

/// Deterministic xorshift64 generator.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::try_from(self.next_u64() % u64::try_from(bound).unwrap_or(u64::MAX)).unwrap_or(0)
    }
}

const TOKENS: &[&[u8]] = &[
    b"[",
    b"]",
    b"{",
    b"}",
    b"\"",
    b":",
    b",",
    b"@context",
    b"@id",
    b"@type",
    b"@graph",
    b"@list",
    b"@set",
    b"@nest",
    b"@reverse",
    b"@included",
    b"@json",
    b"@value",
    b"@language",
    b"@container",
    b"@index",
    b"@embed",
    b"@always",
    b"@import",
    b"@base",
    b"@vocab",
    b"@protected",
    b"@propagate",
    b"_:b0",
    b"http://",
    b"https://x/",
    b"file:///etc/passwd",
    b"\x00",
    b"\xff\xfe",
    b"-1",
    b"1e999",
    b"99999999999999999999",
    b"null",
    b"true",
    b"&a ",
    b"*a",
    b"!!str ",
    b"- ",
    b"\n  ",
];

/// Returns `seed` with one to four random edits.
fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = seed.to_vec();
    for _ in 0..=rng.below(4) {
        if data.is_empty() {
            data.push(b'{');
        }
        let at = rng.below(data.len());
        match rng.below(6) {
            0 => {
                if let Some(byte) = data.get_mut(at) {
                    *byte ^= 1 << rng.below(8);
                }
            }
            1 => data.truncate(at),
            2 => {
                let token = TOKENS.get(rng.below(TOKENS.len())).copied().unwrap_or(b"{");
                data.splice(at..at, token.iter().copied());
            }
            3 => {
                let len = rng.below(64.min(data.len().saturating_sub(at)) + 1);
                let end = at.saturating_add(len).min(data.len());
                data.drain(at..end);
            }
            4 => {
                let len = rng.below(128.min(data.len().saturating_sub(at)) + 1);
                let end = at.saturating_add(len).min(data.len());
                let chunk = data.get(at..end).map(<[u8]>::to_vec).unwrap_or_default();
                let to = rng.below(data.len() + 1);
                data.splice(to..to, chunk);
            }
            _ => {
                if let Some(byte) = data.get_mut(at) {
                    *byte = b"{}[]\":,@ \n"[rng.below(10)];
                }
            }
        }
    }
    data
}

/// Feeds one input to every JSON-LD entry point; results are discarded,
/// only panics, overflows, and the allocation cap matter.
fn exercise_json(bytes: &[u8]) {
    let options = JsonLdOptions::default();
    let limits = JsonLdLimits::default();
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let _validated = validate_streaming_form(text, &limits);
    let _expanded = expand_streaming(text, &options);
    let _compacted = compact_streaming(text, &json!({"@vocab": "http://example.com/"}), &options);
    let _quads = to_quads_streaming(text, &options, None);
    if let Ok(nodes) = parse_streaming_graph(text, &limits) {
        for _node in nodes.take(64) {}
    }
    if let Ok(nodes) = expand_streaming_graph(text, &options) {
        for _node in nodes.take(64) {}
    }
    let Ok(document) = parse_document(text, &limits) else {
        return;
    };
    let _expanded = expand(&document, &options);
    let _compacted = compact(&document, &document, &options);
    let _framed = frame(&document, &json!({}), &options);
    let _self_framed = frame(&document, &document, &options);
    let _yaml = to_yaml_ld(&document);
    let _written = write_streaming_document(&document);
    if let Ok(batches) = to_quads(&document, &options, None) {
        let _from = from_quads(&batches);
        let _streamed = from_quads_streaming(&batches);
    }
}

/// Feeds one input to the YAML-LD entry points under both profiles.
fn exercise_yaml(bytes: &[u8]) {
    for profile in [YamlLdProfile::Basic, YamlLdProfile::Extended] {
        let options = YamlLdOptions {
            profile,
            ..YamlLdOptions::default()
        };
        if let Ok(document) = parse_yaml_ld_bytes(bytes, &options) {
            let _expanded = expand(&document, &options.jsonld);
            let _yaml = to_yaml_ld(&document);
        }
    }
}

fn json_seeds() -> Vec<Vec<u8>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/w3c");
    let mut seeds = Vec::new();
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "json")
                && let Ok(bytes) = std::fs::read(&path)
            {
                seeds.push(bytes);
            }
        }
    }
    seeds.sort();
    seeds.push(
        br#"{"@context": {"@vocab": "http://example.com/", "knows": {"@type": "@id"},
            "n": "@nest", "j": {"@id": "http://example.com/j", "@type": "@json"},
            "l": {"@container": "@list"}, "s": {"@context": {"x": "http://x/"}}},
            "@graph": [{"@id": "http://example.com/a", "knows": "http://example.com/b",
            "n": {"name": "A"}, "j": {"k": [1, 2]}, "l": [[1], [2, [3]]],
            "s": {"x": "y"}, "@reverse": {"http://example.com/r": {"@id": "_:b1"}}},
            {"@id": "http://example.com/b", "knows": "http://example.com/a"}]}"#
            .to_vec(),
    );
    seeds
}

fn yaml_seeds() -> Vec<Vec<u8>> {
    vec![
        b"\"@context\":\n  \"@vocab\": \"http://example.com/\"\n\"@id\": \"http://example.com/a\"\nname: Alice\nknows:\n  - \"@id\": \"http://example.com/b\"\n".to_vec(),
        b"a: &a [x, y]\nb: [*a, *a]\n\"@id\": http://example.com/s\n".to_vec(),
        b"--- \n\"@context\": {\"@vocab\": \"http://e/\"}\nv: !<http://www.w3.org/2001/XMLSchema#integer> 5\n---\n- 1\n- [2, {b: 3}]\n".to_vec(),
    ]
}

/// Runs `exercise` over `ITERATIONS` mutations of `seeds` on a small stack
/// and returns how many inputs panicked, with the first one.
fn smoke(name: &str, seeds: Vec<Vec<u8>>, exercise: fn(&[u8])) -> (usize, Option<Vec<u8>>) {
    let mut seed_bits = 0x9E37_79B9_7F4A_7C15_u64;
    for byte in name.bytes() {
        seed_bits = seed_bits.rotate_left(5) ^ u64::from(byte);
    }
    let handle = std::thread::Builder::new()
        .stack_size(SMALL_STACK_BYTES)
        .spawn(move || {
            let mut rng = Rng(seed_bits.max(1));
            let mut panicked = 0_usize;
            let mut first = None;
            for seed in &seeds {
                if catch_unwind(AssertUnwindSafe(|| exercise(seed))).is_err() {
                    panicked += 1;
                    first.get_or_insert_with(|| seed.clone());
                }
            }
            for _ in 0..ITERATIONS {
                let seed = seeds
                    .get(rng.below(seeds.len()))
                    .cloned()
                    .unwrap_or_default();
                let input = mutate(&seed, &mut rng);
                if catch_unwind(AssertUnwindSafe(|| exercise(&input))).is_err() {
                    panicked += 1;
                    first.get_or_insert(input);
                }
            }
            (panicked, first)
        })
        .expect("spawn the small-stack thread");
    handle.join().expect("the smoke loop itself must not panic")
}

#[test]
fn mutated_json_ld_never_panics_or_aborts() {
    let (panicked, first) = smoke("json-ld", json_seeds(), exercise_json);
    assert_eq!(
        panicked,
        0,
        "first panicking input: {:?}",
        first.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    );
}

#[test]
fn mutated_yaml_ld_never_panics_or_aborts() {
    let (panicked, first) = smoke("yaml-ld", yaml_seeds(), exercise_yaml);
    assert_eq!(
        panicked,
        0,
        "first panicking input: {:?}",
        first.map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    );
}

#[test]
fn value_inputs_built_in_code_are_bounded() {
    // `Value` inputs bypass the parser's own 128-level limit; one 200 deep
    // (beyond the default 128) must be refused, not recursed into.
    let mut deep = json!("leaf");
    for _ in 0..200 {
        deep = Value::Array(vec![deep]);
    }
    let options = JsonLdOptions::default();
    let handle = std::thread::Builder::new()
        .stack_size(SMALL_STACK_BYTES)
        .spawn(move || {
            assert!(expand(&deep, &options).is_err());
            assert!(compact(&json!({}), &deep, &options).is_err());
            assert!(to_yaml_ld(&deep).is_err());
            std::mem::forget(deep);
        })
        .expect("spawn the small-stack thread");
    handle.join().expect("bounded inputs must not panic");
}
