// Rust guideline compliant 2026-02-21
//! Hostile `DoPut` / `DoExchange` payloads against a real localhost server.
//!
//! Kept in its own test binary: before the per-message preflight existed, the
//! decompression bomb aborted the whole process, which no harness can catch.

use arrow_array::RecordBatch;
use arrow_flight::{
    FlightData, FlightDescriptor,
    encode::{DictionaryHandling, FlightDataEncoderBuilder},
    flight_service_client::FlightServiceClient,
};
use arrow_ipc::{CompressionType, MessageHeader, root_as_message, writer::IpcWriteOptions};
use futures::{StreamExt, TryStreamExt, stream};
use oxrdf::{GraphName, Literal, NamedNode, Quad, Term};
use quad_fast_core::{QuadBatchBuilder, QuadLimits};
use quad_fast_flight::serve;
use tonic::{Code, transport::Channel};

fn contract_batch(rows: u64) -> RecordBatch {
    let mut builder = QuadBatchBuilder::new(QuadLimits::default());
    for index in 0..rows {
        let quad = Quad::new(
            NamedNode::new(format!("http://example.com/s/{index}")).unwrap(),
            NamedNode::new("http://example.com/p").unwrap(),
            Term::Literal(Literal::new_simple_literal(format!("object {index}"))),
            GraphName::DefaultGraph,
        );
        builder.push(quad.as_ref(), None).unwrap();
    }
    builder.finish().unwrap()
}

async fn encode(batch: RecordBatch, options: IpcWriteOptions) -> Vec<FlightData> {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), "d".to_owned()]);
    FlightDataEncoderBuilder::new()
        .with_options(options)
        .with_flight_descriptor(Some(descriptor))
        .with_dictionary_handling(DictionaryHandling::Resend)
        .build(stream::iter([Ok(batch)]))
        .try_collect()
        .await
        .unwrap()
}

/// Index of the first data-carrying message and of one of its buffers.
fn first_buffer(frames: &[FlightData], min_len: i64) -> (usize, usize, usize) {
    for (index, frame) in frames.iter().enumerate() {
        let message = root_as_message(&frame.data_header).unwrap();
        let header = match message.header_type() {
            MessageHeader::RecordBatch => message.header_as_record_batch(),
            MessageHeader::DictionaryBatch => message
                .header_as_dictionary_batch()
                .and_then(|dictionary| dictionary.data()),
            _ => None,
        };
        let Some(header) = header else { continue };
        for buffer in header.buffers().unwrap() {
            if buffer.length() >= min_len {
                return (
                    index,
                    usize::try_from(buffer.offset()).unwrap(),
                    usize::try_from(buffer.length()).unwrap(),
                );
            }
        }
    }
    panic!("no data buffer found");
}

async fn connect(addr: std::net::SocketAddr) -> FlightServiceClient<Channel> {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    FlightServiceClient::new(channel)
}

async fn put_code(client: &mut FlightServiceClient<Channel>, frames: Vec<FlightData>) -> Code {
    match client.do_put(stream::iter(frames)).await {
        Err(status) => status.code(),
        Ok(response) => match response.into_inner().try_collect::<Vec<_>>().await {
            Ok(_) => Code::Ok,
            Err(status) => status.code(),
        },
    }
}

async fn exchange_code(client: &mut FlightServiceClient<Channel>, frames: Vec<FlightData>) -> Code {
    match client.do_exchange(stream::iter(frames)).await {
        Err(status) => status.code(),
        Ok(response) => {
            let mut results = response.into_inner();
            loop {
                match results.next().await {
                    None => return Code::Ok,
                    Some(Ok(_)) => {}
                    Some(Err(status)) => return status.code(),
                }
            }
        }
    }
}

#[tokio::test]
async fn compressed_buffer_declaring_a_huge_length_is_refused_not_allocated() {
    let server = serve("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut client = connect(server.local_addr()).await;

    let options = IpcWriteOptions::default()
        .try_with_compression(Some(CompressionType::LZ4_FRAME))
        .unwrap();
    let mut frames = encode(contract_batch(8), options).await;
    let (message, offset, _length) = first_buffer(&frames, 8);
    let mut body = frames[message].data_body.to_vec();
    // 4 EiB: fits isize, so `Vec::with_capacity` asks the allocator for it.
    body[offset..offset + 8].copy_from_slice(&(1_i64 << 62).to_le_bytes());
    frames[message].data_body = body.into();

    let put = put_code(&mut client, frames.clone()).await;
    assert_eq!(put, Code::InvalidArgument, "DoPut");
    let exchange = exchange_code(&mut client, frames).await;
    assert_eq!(exchange, Code::InvalidArgument, "DoExchange");

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn buffer_pointing_outside_the_body_is_a_status_not_a_panic() {
    let server = serve("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut client = connect(server.local_addr()).await;

    let mut frames = encode(contract_batch(8), IpcWriteOptions::default()).await;
    let (message, offset, _length) = first_buffer(&frames, 1);
    // Keep the header, cut the body short: every later buffer now points
    // past the end of the bytes actually received.
    let body = frames[message].data_body.slice(..offset);
    frames[message].data_body = body;

    let put = put_code(&mut client, frames.clone()).await;
    assert_eq!(put, Code::InvalidArgument, "DoPut");
    let exchange = exchange_code(&mut client, frames).await;
    assert_eq!(exchange, Code::InvalidArgument, "DoExchange");

    // The server is still serving.
    let healthy = encode(contract_batch(2), IpcWriteOptions::default()).await;
    assert_eq!(put_code(&mut client, healthy).await, Code::Ok);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn zstd_buffer_declaring_a_huge_length_is_refused_before_allocation() {
    let server = serve("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut client = connect(server.local_addr()).await;

    let options = IpcWriteOptions::default()
        .try_with_compression(Some(CompressionType::ZSTD))
        .unwrap();
    let mut frames = encode(contract_batch(8), options).await;
    let (message, offset, _length) = first_buffer(&frames, 8);
    let mut body = frames[message].data_body.to_vec();
    body[offset..offset + 8].copy_from_slice(&(1_i64 << 62).to_le_bytes());
    frames[message].data_body = body.into();

    let put = put_code(&mut client, frames.clone()).await;
    assert_eq!(put, Code::ResourceExhausted, "DoPut");
    let exchange = exchange_code(&mut client, frames).await;
    assert_eq!(exchange, Code::ResourceExhausted, "DoExchange");

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn zstd_round_trips_and_lz4_is_refused() {
    let server = serve("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut client = connect(server.local_addr()).await;

    let zstd = IpcWriteOptions::default()
        .try_with_compression(Some(CompressionType::ZSTD))
        .unwrap();
    let frames = encode(contract_batch(8), zstd.clone()).await;
    assert_eq!(put_code(&mut client, frames).await, Code::Ok, "zstd DoPut");
    let response = client
        .do_get(arrow_flight::Ticket::new("d".to_owned()))
        .await
        .unwrap();
    let batches: Vec<RecordBatch> =
        arrow_flight::decode::FlightRecordBatchStream::new_from_flight_data(
            response
                .into_inner()
                .map_err(arrow_flight::error::FlightError::from),
        )
        .try_collect()
        .await
        .unwrap();
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 8);
    assert_eq!(
        batches[0],
        contract_batch(8),
        "zstd DoPut reads back unchanged"
    );
    let frames = encode(contract_batch(8), zstd).await;
    assert_eq!(
        exchange_code(&mut client, frames).await,
        Code::Ok,
        "zstd DoExchange"
    );

    let lz4 = IpcWriteOptions::default()
        .try_with_compression(Some(CompressionType::LZ4_FRAME))
        .unwrap();
    let frames = encode(contract_batch(8), lz4).await;
    assert_eq!(
        put_code(&mut client, frames).await,
        Code::InvalidArgument,
        "lz4 stays refused"
    );

    server.shutdown().await.unwrap();
}
