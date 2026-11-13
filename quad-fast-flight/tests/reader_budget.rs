// Rust guideline compliant 2026-02-21
//! The store byte budget holds while readers hold a dataset, and the largest
//! batch `DoPut` accepts always reads back.

use std::time::Duration;

use arrow_array::RecordBatch;
use arrow_flight::{
    Action, FlightData, FlightDescriptor, Ticket,
    decode::FlightRecordBatchStream,
    encode::{DictionaryHandling, FlightDataEncoderBuilder},
    error::FlightError,
    flight_service_client::FlightServiceClient,
};
use arrow_ipc::{MetadataVersion, writer::IpcWriteOptions};
use futures::{StreamExt, TryStreamExt, stream};
use oxrdf::{GraphName, Literal, NamedNode, Quad, Term};
use quad_fast_core::{QuadBatchBuilder, QuadLimits};
use quad_fast_flight::{DatasetLimits, serve_with_limits};
use tonic::{Code, transport::Channel};

const MIB: usize = 1024 * 1024;

fn literal_batch(index: usize, literal_bytes: usize) -> RecordBatch {
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

async fn frames(
    name: &str,
    batches: Vec<RecordBatch>,
    options: IpcWriteOptions,
) -> Vec<FlightData> {
    let descriptor = FlightDescriptor::new_path(vec!["datasets".to_owned(), name.to_owned()]);
    FlightDataEncoderBuilder::new()
        .with_options(options)
        .with_flight_descriptor(Some(descriptor))
        .with_dictionary_handling(DictionaryHandling::Resend)
        .build(stream::iter(batches.into_iter().map(Ok)))
        .try_collect()
        .await
        .unwrap()
}

async fn put(client: &mut FlightServiceClient<Channel>, frames: Vec<FlightData>) -> Code {
    match client.do_put(stream::iter(frames)).await {
        Err(status) => status.code(),
        Ok(response) => match response.into_inner().try_collect::<Vec<_>>().await {
            Ok(_) => Code::Ok,
            Err(status) => status.code(),
        },
    }
}

async fn drop_dataset(client: &mut FlightServiceClient<Channel>, name: &str) {
    let mut results = client
        .do_action(Action::new("drop_dataset", name.to_owned()))
        .await
        .unwrap()
        .into_inner();
    while results.message().await.unwrap().is_some() {}
}

async fn connect(addr: std::net::SocketAddr) -> FlightServiceClient<Channel> {
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    FlightServiceClient::new(channel)
}

/// Put 16 MiB, open a `DoGet` and never read it, drop the dataset, repeat.
///
/// The dataset's bytes stay charged while a reader still holds them, so the
/// second round must be refused under a 24 MiB store budget; once the idle
/// reader is cut off, the budget is free again. 16 MiB is well above what
/// HTTP/2 flow control lets the server push into an unread stream, so the
/// reader really is holding the dataset.
#[tokio::test]
async fn unread_readers_keep_their_dataset_charged_until_cut_off() {
    let idle = Duration::from_secs(2);
    let limits = DatasetLimits {
        max_dataset_bytes: 20 * MIB,
        max_store_bytes: 24 * MIB,
        idle_timeout: idle,
        ..DatasetLimits::default()
    };
    let server = serve_with_limits("127.0.0.1:0".parse().unwrap(), limits)
        .await
        .unwrap();
    let mut client = connect(server.local_addr()).await;
    let sixteen_mib = || {
        (0..16)
            .map(|index| literal_batch(index, MIB - 4_096))
            .collect::<Vec<_>>()
    };

    let mut held = Vec::new();
    let mut codes = Vec::new();
    for round in 0..8 {
        let code = put(
            &mut client,
            frames("d", sixteen_mib(), IpcWriteOptions::default()).await,
        )
        .await;
        codes.push(code);
        if code != Code::Ok {
            break;
        }
        // A separate connection per reader, so an unread stream cannot
        // stall the writer's connection-level flow control.
        let mut reader = connect(server.local_addr()).await;
        held.push(
            reader
                .do_get(Ticket::new("d".to_owned()))
                .await
                .unwrap()
                .into_inner(),
        );
        drop_dataset(&mut client, "d").await;
        eprintln!("reader-budget round {round}: put {code:?}");
    }
    eprintln!("reader-budget codes {codes:?}");
    assert_eq!(
        codes,
        [Code::Ok, Code::ResourceExhausted],
        "a dropped dataset still held by an open reader must stay charged"
    );

    // The idle readers are cut off, which releases their datasets.
    tokio::time::sleep(idle * 2).await;
    let code = put(
        &mut client,
        frames("d", sixteen_mib(), IpcWriteOptions::default()).await,
    )
    .await;
    assert_eq!(
        code,
        Code::Ok,
        "the budget is free once idle readers are gone"
    );
    let mut first = held.remove(0);
    let mut outcome = Ok(());
    while let Some(item) = first.next().await {
        if let Err(status) = item {
            outcome = Err(status.code());
        }
    }
    assert_eq!(
        outcome,
        Err(Code::DeadlineExceeded),
        "a reader that stopped reading ends with an error, never a silent short stream"
    );

    server.shutdown().await.unwrap();
}

/// Largest single-row literal a `DoPut` with `alignment` accepts.
async fn largest_accepted_row(
    client: &mut FlightServiceClient<Channel>,
    alignment: usize,
) -> usize {
    let options = IpcWriteOptions::try_new(alignment, false, MetadataVersion::V5).unwrap();
    let (mut accepted, mut refused) = (MIB, 5 * MIB);
    while refused - accepted > 1 {
        let middle = accepted + (refused - accepted) / 2;
        let code = put(
            client,
            frames("probe", vec![literal_batch(0, middle)], options.clone()).await,
        )
        .await;
        match code {
            Code::Ok => accepted = middle,
            Code::ResourceExhausted | Code::OutOfRange => refused = middle,
            other => panic!("unexpected {other:?} for a {middle}-byte row"),
        }
    }
    accepted
}

async fn get_rows(client: &mut FlightServiceClient<Channel>, name: &str) -> Result<usize, Code> {
    let response = client
        .do_get(Ticket::new(name.to_owned()))
        .await
        .map_err(|status| status.code())?;
    let batches: Vec<RecordBatch> = FlightRecordBatchStream::new_from_flight_data(
        response.into_inner().map_err(FlightError::from),
    )
    .try_collect()
    .await
    .map_err(|error| match error {
        FlightError::Tonic(status) => status.code(),
        _ => Code::Internal,
    })?;
    Ok(batches.iter().map(RecordBatch::num_rows).sum())
}

async fn exchange_rows(
    client: &mut FlightServiceClient<Channel>,
    frames: Vec<FlightData>,
) -> Result<usize, Code> {
    let response = client
        .do_exchange(stream::iter(frames))
        .await
        .map_err(|status| status.code())?;
    let batches: Vec<RecordBatch> = FlightRecordBatchStream::new_from_flight_data(
        response.into_inner().map_err(FlightError::from),
    )
    .try_collect()
    .await
    .map_err(|error| match error {
        FlightError::Tonic(status) => status.code(),
        _ => Code::Internal,
    })?;
    Ok(batches.iter().map(RecordBatch::num_rows).sum())
}

#[tokio::test]
async fn the_largest_row_doput_accepts_reads_back_through_doget_and_doexchange() {
    let server = serve_with_limits("127.0.0.1:0".parse().unwrap(), DatasetLimits::default())
        .await
        .unwrap();
    // A default client: tonic's 4 MiB decoding limit, as most clients have.
    let mut client = connect(server.local_addr()).await;
    for alignment in [8, 64] {
        let largest = largest_accepted_row(&mut client, alignment).await;
        eprintln!("largest accepted single row at alignment {alignment}: {largest} bytes");
        let options = IpcWriteOptions::try_new(alignment, false, MetadataVersion::V5).unwrap();
        let batch = vec![literal_batch(0, largest)];
        assert_eq!(
            put(
                &mut client,
                frames("big", batch.clone(), options.clone()).await
            )
            .await,
            Code::Ok
        );
        assert_eq!(
            get_rows(&mut client, "big").await,
            Ok(1),
            "DoGet at alignment {alignment}"
        );
        assert_eq!(
            exchange_rows(&mut client, frames("big", batch, options).await).await,
            Ok(1),
            "DoExchange at alignment {alignment}"
        );
    }
    server.shutdown().await.unwrap();
}
