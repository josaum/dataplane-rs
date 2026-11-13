// Rust guideline compliant 2026-02-21
//! Peak memory of a real localhost server under hostile `DoPut` clients.
//!
//! A counting global allocator records the process-wide peak; client and
//! server share the process, so the peak bounds both. Run it in release for
//! the numbers quoted in reviews:
//! `cargo test --release -p quad-fast-flight --test hostile_memory -- --nocapture`.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use arrow_array::RecordBatch;
use arrow_flight::{
    FlightData, FlightDescriptor,
    encode::{DictionaryHandling, FlightDataEncoderBuilder},
    flight_service_client::FlightServiceClient,
};
use futures::{StreamExt, TryStreamExt, stream};
use oxrdf::{GraphName, Literal, NamedNode, Quad, Term};
use quad_fast_core::{QuadBatchBuilder, QuadLimits};
use quad_fast_flight::{DatasetLimits, serve_with_limits};
use tonic::Code;

/// Counts live and peak heap bytes.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` unchanged; the counters are
// plain atomics and never touch the allocation itself.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded with the caller's layout contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded with the caller's pointer and layout contract.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const MIB: usize = 1024 * 1024;

/// One contract batch whose single literal is `literal_bytes` long.
fn fat_batch(index: usize, literal_bytes: usize) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    let quad = Quad::new(
        NamedNode::new(format!("http://example.com/s/{index}")).unwrap(),
        NamedNode::new("http://example.com/p").unwrap(),
        Term::Literal(Literal::new_simple_literal("x".repeat(literal_bytes))),
        GraphName::DefaultGraph,
    );
    builder.push(quad.as_ref(), None).unwrap();
    builder.finish().unwrap()
}

/// Lazily encodes `count` batches so the client never holds them all.
fn hostile_stream(
    count: usize,
    literal_bytes: usize,
) -> impl futures::Stream<Item = FlightData> + Send + 'static {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), "fat".to_owned()]);
    FlightDataEncoderBuilder::new()
        .with_flight_descriptor(Some(descriptor))
        .with_dictionary_handling(DictionaryHandling::Resend)
        .build(stream::iter(
            (0..count).map(move |index| Ok(fat_batch(index, literal_bytes))),
        ))
        .map(|data| data.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_puts_stay_within_the_byte_budget() {
    let limits = DatasetLimits {
        max_dataset_bytes: 16 * MIB,
        max_store_bytes: 24 * MIB,
        ..DatasetLimits::default()
    };
    let server = serve_with_limits("127.0.0.1:0".parse().unwrap(), limits)
        .await
        .unwrap();
    let channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", server.local_addr()))
            .unwrap()
            .connect()
            .await
            .unwrap();
    let mut client = FlightServiceClient::new(channel);
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    // 1. One upload of 256 one-MiB literals: 256 MiB offered.
    let started = Instant::now();
    let code = match client.do_put(hostile_stream(256, MIB)).await {
        Err(status) => status.code(),
        Ok(response) => match response.into_inner().try_collect::<Vec<_>>().await {
            Ok(_) => Code::Ok,
            Err(status) => status.code(),
        },
    };
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    eprintln!(
        "hostile-memory fat-put code={code:?} peak_mib={} elapsed_ms={}",
        peak / MIB,
        started.elapsed().as_millis()
    );
    assert_eq!(code, Code::ResourceExhausted);
    assert!(
        peak < 96 * MIB,
        "peak {} MiB for a 16 MiB dataset budget",
        peak / MIB
    );

    // 2. Four concurrent uploads of 12 MiB each: each fits the dataset budget,
    //    together they exceed the store budget, which counts in-flight bytes.
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let started = Instant::now();
    let mut uploads = Vec::new();
    for index in 0..4 {
        let mut client = client.clone();
        uploads.push(tokio::spawn(async move {
            let descriptor =
                FlightDescriptor::new_path(vec!["datasets".to_owned(), format!("c{index}")]);
            let frames = FlightDataEncoderBuilder::new()
                .with_flight_descriptor(Some(descriptor))
                .with_dictionary_handling(DictionaryHandling::Resend)
                .build(stream::iter(
                    (0..12).map(move |batch| Ok(fat_batch(batch, MIB))),
                ))
                .map(|data| data.unwrap());
            match client.do_put(frames).await {
                Err(status) => status.code(),
                Ok(response) => match response.into_inner().try_collect::<Vec<_>>().await {
                    Ok(_) => Code::Ok,
                    Err(status) => status.code(),
                },
            }
        }));
    }
    let mut codes = Vec::new();
    for upload in uploads {
        codes.push(upload.await.unwrap());
    }
    let peak = PEAK.load(Ordering::Relaxed) - baseline;
    eprintln!(
        "hostile-memory concurrent-puts codes={codes:?} peak_mib={} elapsed_ms={}",
        peak / MIB,
        started.elapsed().as_millis()
    );
    assert!(codes.contains(&Code::ResourceExhausted), "{codes:?}");
    assert!(
        peak < 128 * MIB,
        "peak {} MiB for a 24 MiB store budget",
        peak / MIB
    );

    // 3. Tens of thousands of tiny batches: refused at the batch limit.
    let started = Instant::now();
    let code = match client.do_put(hostile_stream(20_000, 1)).await {
        Err(status) => status.code(),
        Ok(response) => match response.into_inner().try_collect::<Vec<_>>().await {
            Ok(_) => Code::Ok,
            Err(status) => status.code(),
        },
    };
    eprintln!(
        "hostile-memory tiny-batches code={code:?} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    assert_eq!(code, Code::ResourceExhausted);

    server.shutdown().await.unwrap();
}
