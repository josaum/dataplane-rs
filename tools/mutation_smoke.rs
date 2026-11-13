// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Deterministic malformed-input smoke harness shared by the decoder crates.
//!
//! A decoder that reads untrusted bytes must return an error on bad input; it
//! must not panic, overflow the stack, or allocate without bound. This module
//! mutates valid seed inputs with a fixed-seed generator and feeds them to a
//! decode closure, so each crate can assert that property in its own tests.
//!
//! It is included by path rather than built as a crate, so it adds no
//! workspace member and no dependency:
//!
//! ```ignore
//! #[path = "../../tools/mutation_smoke.rs"]
//! mod smoke;
//!
//! #[global_allocator]
//! static ALLOCATOR: smoke::CappedAllocator = smoke::CappedAllocator;
//! ```
//!
//! Everything is deterministic: a fixed seed and a fixed iteration count,
//! never wall-clock time, so a failure reproduces on any machine. Adapted
//! from the parsers-rs `tools/mutation_smoke.rs` harness, with the token
//! list replaced by CBOR heads and protobuf varints.

#![allow(
    dead_code,
    reason = "each including test binary uses a different subset"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Most memory one test binary may hold live before it is aborted: 1 GiB.
///
/// Far above anything a decoder needs for the inputs used here, and far
/// below what would exhaust a CI runner. A decoder that sizes an allocation
/// from an attacker-controlled field trips this and aborts the test binary
/// with a message instead of taking the machine down with it.
pub const ALLOCATION_CAP_BYTES: usize = 1 << 30;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Cumulative bytes ever allocated, for work-amplification assertions.
static TOTAL_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Set once the cap has tripped and its message is being written, so the
/// report's own allocation cannot re-trip the cap.
static REPORTING_CAP: AtomicBool = AtomicBool::new(false);

/// A global allocator that aborts the process once live memory passes
/// [`ALLOCATION_CAP_BYTES`].
#[derive(Debug)]
pub struct CappedAllocator;

impl CappedAllocator {
    fn charge(size: usize) {
        TOTAL_BYTES.fetch_add(size, Ordering::Relaxed);
        let live = LIVE_BYTES
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        if live > ALLOCATION_CAP_BYTES && !REPORTING_CAP.swap(true, Ordering::SeqCst) {
            // `abort` does not allocate; a panic here would try to allocate
            // its message. The write error is ignored (closed pipe).
            let _ = writeln!(
                std::io::stderr(),
                "mutation_smoke: allocation cap exceeded ({size} byte request, {live} bytes live); \
                 a decoder allocated without bound"
            );
            std::process::abort();
        }
    }
}

// SAFETY: every method forwards to `System` with the caller's unchanged
// pointer and layout; the only added behavior is byte accounting and an abort.
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
        // SAFETY: `pointer` came from this allocator, which delegates to the
        // system allocator with the same layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > layout.size() {
            Self::charge(new_size - layout.size());
        } else {
            LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        // SAFETY: forwarding the original pointer and layout, and the requested
        // size, to the system allocator that created the allocation.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

/// Returns the cumulative number of bytes allocated so far by this process.
///
/// Tests run in parallel share the counter, so a work assertion built on it
/// must use a margin far above what the other tests allocate.
pub fn total_allocated() -> usize {
    TOTAL_BYTES.load(Ordering::Relaxed)
}

/// Serializes tests that measure the process-wide allocation counters.
///
/// The counters are global, so a test that asserts on them must hold this
/// lock or a concurrently running test's allocations pollute its numbers.
pub fn measure_alone() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Returns the bytes currently allocated and not yet freed by this process.
pub fn live_allocated() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// A small deterministic generator (xorshift64); no external crate, no clock.
#[derive(Debug)]
pub struct Rng(u64);

impl Rng {
    /// Creates a generator from a non-zero seed.
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    /// Returns the next 64 pseudo-random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// Returns a value in `0..bound`, or 0 when `bound` is 0.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }
}

/// Byte strings that tend to reach untested branches of binary decoders:
/// CBOR heads with extreme or reserved arguments, indefinite-length markers,
/// tags, and protobuf varints that declare huge lengths.
const TOKENS: &[&[u8]] = &[
    // CBOR: 8-byte argument heads declaring 2^63 for bytes, text, array, map.
    b"\x5b\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x7b\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x9b\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\xbb\x80\x00\x00\x00\x00\x00\x00\x00",
    // CBOR: indefinite-length heads and the break byte.
    b"\x5f",
    b"\x7f",
    b"\x9f",
    b"\xbf",
    b"\xff",
    // CBOR: reserved additional information, tags, bignums, half floats.
    b"\x1c",
    b"\xc2\x41\x01",
    b"\xc3\x41\x01",
    b"\xd9\xcb\x1d",
    b"\xc6\xc6\xc6\xc6",
    b"\xf9\x7c\x00",
    b"\xf9\x7e\x00",
    b"\xf7",
    // Protobuf: field 1 length-delimited with maximal varint lengths.
    b"\x0a\xff\xff\xff\xff\x0f",
    b"\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
    b"\x12\x80\x80\x80\x80\x08",
    b"\x08\xff\xff\xff\xff\x0f",
    b"\x0a\x00",
    b"\x00",
];

/// Returns `seed` with one to four random edits applied.
///
/// Edits are byte replacement, bit flips, truncation, token insertion, range
/// deletion, range duplication, and random overwrites.
pub fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut data = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        if data.is_empty() {
            data.push(0);
        }
        match rng.below(7) {
            0 => {
                let at = rng.below(data.len());
                data[at] = rng.next_u64() as u8;
            }
            1 => {
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
            2 => {
                let at = rng.below(data.len());
                data.truncate(at);
            }
            3 => {
                let at = rng.below(data.len() + 1);
                let token = TOKENS[rng.below(TOKENS.len())];
                data.splice(at..at, token.iter().copied());
            }
            4 => {
                let at = rng.below(data.len());
                let len = rng.below(64.min(data.len() - at) + 1);
                data.drain(at..at + len);
            }
            5 => {
                let at = rng.below(data.len());
                let len = rng.below(128.min(data.len() - at) + 1);
                let chunk = data[at..at + len].to_vec();
                let to = rng.below(data.len() + 1);
                data.splice(to..to, chunk);
            }
            _ => {
                let at = rng.below(data.len());
                let len = rng.below(16.min(data.len() - at) + 1);
                for byte in &mut data[at..at + len] {
                    *byte = rng.next_u64() as u8;
                }
            }
        }
    }
    data
}

/// Stack size of the thread [`run_on_small_stack`] uses: 256 KiB.
///
/// Matches the smallest stack a consumer realistically runs a decoder on (a
/// worker thread with a reduced stack), well below the 8 MiB main thread, so
/// a recursion limit that only holds on the main thread is caught.
pub const SMALL_STACK_BYTES: usize = 256 * 1024;

/// Runs `body` on a thread with a [`SMALL_STACK_BYTES`] stack.
///
/// # Panics
///
/// Panics if the thread cannot be spawned or `body` panics. A stack
/// overflow aborts the whole test binary.
pub fn run_on_small_stack<F>(body: F)
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(SMALL_STACK_BYTES)
        .spawn(body)
        .expect("spawn small-stack thread")
        .join()
        .expect("decoder panicked on a small stack");
}

/// Feeds `iterations` mutated seeds to `decode` and returns every panic.
///
/// Each entry is the mutated input and the panic's `file:line`. Inputs are
/// chosen and mutated by a generator seeded from `name`.
pub fn collect_panics<F>(
    name: &str,
    seeds: &[Vec<u8>],
    iterations: usize,
    decode: F,
) -> Vec<(Vec<u8>, String)>
where
    F: Fn(&[u8]),
{
    static LAST_PANIC_LOCATION: Mutex<Option<String>> = Mutex::new(None);

    assert!(!seeds.is_empty(), "mutation smoke needs at least one seed");
    let mut seed_bits = 0x9E37_79B9_7F4A_7C15u64;
    for byte in name.bytes() {
        seed_bits = seed_bits.rotate_left(5) ^ u64::from(byte);
    }
    let mut rng = Rng::new(seed_bits);

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map_or_else(
            || "unknown location".to_string(),
            |location| format!("{}:{}", location.file(), location.line()),
        );
        if let Ok(mut slot) = LAST_PANIC_LOCATION.lock() {
            *slot = Some(location);
        }
    }));

    let mut panics = Vec::new();
    for _ in 0..iterations {
        let input = mutate(&seeds[rng.below(seeds.len())], &mut rng);
        if catch_unwind(AssertUnwindSafe(|| decode(&input))).is_err() {
            let location = LAST_PANIC_LOCATION
                .lock()
                .ok()
                .and_then(|mut slot| slot.take())
                .unwrap_or_else(|| "unknown location".to_string());
            panics.push((input, location));
        }
    }

    std::panic::set_hook(previous_hook);
    panics
}

/// Asserts that no mutated input makes `decode` panic.
///
/// # Panics
///
/// Panics with each distinct panic location, its count, and one reproducing
/// input (as escaped bytes) when any mutated input panics.
pub fn assert_no_panics<F>(name: &str, seeds: &[Vec<u8>], iterations: usize, decode: F)
where
    F: Fn(&[u8]),
{
    let panics = collect_panics(name, seeds, iterations, decode);
    if panics.is_empty() {
        return;
    }
    let mut by_location: std::collections::BTreeMap<&str, (usize, &[u8])> =
        std::collections::BTreeMap::new();
    for (input, location) in &panics {
        let entry = by_location.entry(location).or_insert((0, input));
        entry.0 += 1;
        if input.len() < entry.1.len() {
            entry.1 = input;
        }
    }
    let mut report = format!(
        "{name}: {} of {iterations} malformed inputs panicked at {} location(s)\n",
        panics.len(),
        by_location.len()
    );
    for (location, (count, input)) in &by_location {
        let shown: String = input
            .iter()
            .take(400)
            .flat_map(|byte| std::ascii::escape_default(*byte))
            .map(char::from)
            .collect();
        let _ = writeln!(
            std::io::stderr(),
            "  {count}x {location}\n    smallest input ({} bytes): b\"{shown}\"",
            input.len()
        );
        report.push_str(location);
        report.push('\n');
    }
    panic!("{report}");
}
