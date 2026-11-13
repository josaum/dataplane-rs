// Rust guideline compliant 2026-02-21
//! Bounded topic registries backed by tokio broadcast channels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jelly_fast_core::proto::{
    RdfStreamFrame, RdfStreamOptions,
    patch::{RdfPatchFrame, RdfPatchOptions},
};
use tokio::sync::broadcast;
use tonic::Status;

/// Default per-topic broadcast capacity, in frames.
///
/// Bounds server memory per topic at roughly `capacity` retained frames
/// (a frame of default encoder settings holds up to 8192 quad rows).
/// A subscriber that falls more than this many frames behind receives an
/// explicit `DATA_LOSS` status instead of silently missing frames;
/// raising the bound trades memory for slow-subscriber tolerance.
pub const DEFAULT_TOPIC_CAPACITY: usize = 256;

/// Default maximum number of live topics in one registry.
///
/// Every new topic name allocates a broadcast channel, and topics used to be
/// kept forever, so a client could grow the registry without bound by
/// subscribing to fresh names. At the limit, topics with neither a subscriber
/// nor a publisher are pruned first; only then is a new name refused with
/// `RESOURCE_EXHAUSTED`.
pub const DEFAULT_MAX_TOPICS: usize = 1_024;

/// Maximum topic name length, in bytes.
///
/// Topic names are map keys held for the life of the topic; nothing
/// legitimate needs more.
pub const MAX_TOPIC_NAME_BYTES: usize = 256;

/// One pub/sub topic: its broadcast channel and last announced options.
///
/// The channel carries [`Arc<F>`] so fan-out to N subscribers is an
/// identity bump, not N prost copies. That alias is not a signature.
#[derive(Debug)]
struct Topic<F, O> {
    sender: broadcast::Sender<Arc<F>>,
    options: Option<O>,
}

/// Generic bounded topic table shared by both registries.
///
/// Topics are created on first use by either side. Delivery is
/// at-most-once relay: frames published while a topic has no subscriber
/// are not retained (standard pub/sub semantics, documented here so the
/// behavior is explicit rather than a silent drop). Subscribers that lag
/// beyond the bounded channel capacity get an explicit error, never a
/// silent gap.
#[derive(Debug)]
struct Topics<F, O> {
    capacity: usize,
    max_topics: usize,
    topics: Mutex<HashMap<String, Topic<F, O>>>,
}

impl<F: Clone, O: Clone> Topics<F, O> {
    /// Creates a table whose topics buffer at most `capacity` frames.
    fn new(capacity: usize, max_topics: usize) -> Self {
        assert!(capacity > 0, "topic capacity must be nonzero");
        Self {
            capacity,
            max_topics,
            topics: Mutex::new(HashMap::new()),
        }
    }

    /// Locks the table, recovering it after a panic in another holder.
    ///
    /// Every critical section is a single map operation, so a poisoned lock
    /// still guards a consistent map; refusing it would turn one panic into
    /// a permanent outage of every later RPC.
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Topic<F, O>>> {
        self.topics.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the topic named `name`, creating it within the limits.
    fn topic<'t>(
        &self,
        topics: &'t mut HashMap<String, Topic<F, O>>,
        name: &str,
    ) -> Result<&'t mut Topic<F, O>, Status> {
        if name.len() > MAX_TOPIC_NAME_BYTES {
            return Err(Status::invalid_argument(format!(
                "topic name exceeds {MAX_TOPIC_NAME_BYTES} bytes"
            )));
        }
        if !topics.contains_key(name) && topics.len() >= self.max_topics {
            // A topic nobody holds a sender or receiver for is dead: the
            // registry's own sender is the only strong reference left.
            topics.retain(|_, topic| {
                topic.sender.receiver_count() > 0 || topic.sender.strong_count() > 1
            });
            if topics.len() >= self.max_topics {
                return Err(Status::resource_exhausted(format!(
                    "resource_limit: topics: registry already holds the maximum of {} live topics",
                    self.max_topics
                )));
            }
        }
        Ok(topics.entry(name.to_owned()).or_insert_with(|| Topic {
            sender: broadcast::channel(self.capacity).0,
            options: None,
        }))
    }

    /// Registers a publisher, storing `options` as the topic's contract.
    fn register_publisher(
        &self,
        topic: &str,
        options: &O,
    ) -> Result<broadcast::Sender<Arc<F>>, Status> {
        let mut topics = self.lock();
        let topic = self.topic(&mut topics, topic)?;
        topic.options = Some(options.clone());
        Ok(topic.sender.clone())
    }

    /// Subscribes to `topic`, creating it when absent.
    fn subscribe(&self, topic: &str) -> Result<(broadcast::Receiver<Arc<F>>, Option<O>), Status> {
        let mut topics = self.lock();
        let topic = self.topic(&mut topics, topic)?;
        Ok((topic.sender.subscribe(), topic.options.clone()))
    }

    /// Number of topics currently held, live or not yet pruned.
    fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Registry of Jelly RDF pub/sub topics keyed by stream name.
///
/// Topics are created on first use by either side. Delivery is
/// at-most-once relay: frames published while a topic has no subscriber
/// are not retained (standard pub/sub semantics, documented here so the
/// behavior is explicit rather than a silent drop). Subscribers that lag
/// beyond the bounded channel capacity get an explicit error, never a
/// silent gap.
#[derive(Debug)]
pub struct TopicRegistry {
    topics: Topics<RdfStreamFrame, RdfStreamOptions>,
}

impl TopicRegistry {
    /// Creates a registry whose topics buffer at most `capacity` frames.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero; tokio broadcast channels require a
    /// nonzero capacity, and a zero bound would make every topic useless.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_max_topics(capacity, DEFAULT_MAX_TOPICS)
    }

    /// Creates a registry holding at most `max_topics` live topics.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero, as [`TopicRegistry::new`] does.
    #[must_use]
    pub fn with_max_topics(capacity: usize, max_topics: usize) -> Self {
        Self {
            topics: Topics::new(capacity, max_topics),
        }
    }

    /// Number of topics currently held, live or not yet pruned.
    #[must_use]
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }

    /// Registers a publisher, storing `options` as the topic's contract.
    ///
    /// Returns the broadcast sender for `topic`. The stored options are
    /// what subscribers' `requested_options` are checked against.
    pub(crate) fn register_publisher(
        &self,
        topic: &str,
        options: &RdfStreamOptions,
    ) -> Result<broadcast::Sender<Arc<RdfStreamFrame>>, Status> {
        self.topics.register_publisher(topic, options)
    }

    /// Subscribes to `topic`, creating it when absent.
    ///
    /// Returns the receiver and the topic's last announced publisher
    /// options (when a publisher has already registered). Each received
    /// item is an [`Arc`] of the published frame.
    pub(crate) fn subscribe(
        &self,
        topic: &str,
    ) -> Result<
        (
            broadcast::Receiver<Arc<RdfStreamFrame>>,
            Option<RdfStreamOptions>,
        ),
        Status,
    > {
        self.topics.subscribe(topic)
    }
}

impl Default for TopicRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_TOPIC_CAPACITY)
    }
}

/// Registry of Jelly-Patch pub/sub topics keyed by topic name.
///
/// Same relay semantics as [`TopicRegistry`]; the topic name comes from
/// the publish envelope of the dataplane patch service (the vendored
/// `RdfPatchOptions` carries no stream name).
#[derive(Debug)]
pub struct PatchTopicRegistry {
    topics: Topics<RdfPatchFrame, RdfPatchOptions>,
}

impl PatchTopicRegistry {
    /// Creates a registry whose topics buffer at most `capacity` frames.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero; tokio broadcast channels require a
    /// nonzero capacity, and a zero bound would make every topic useless.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_max_topics(capacity, DEFAULT_MAX_TOPICS)
    }

    /// Creates a registry holding at most `max_topics` live topics.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero, as [`PatchTopicRegistry::new`] does.
    #[must_use]
    pub fn with_max_topics(capacity: usize, max_topics: usize) -> Self {
        Self {
            topics: Topics::new(capacity, max_topics),
        }
    }

    /// Number of topics currently held, live or not yet pruned.
    #[must_use]
    pub fn topic_count(&self) -> usize {
        self.topics.len()
    }

    /// Registers a publisher, storing `options` as the topic's contract.
    pub(crate) fn register_publisher(
        &self,
        topic: &str,
        options: &RdfPatchOptions,
    ) -> Result<broadcast::Sender<Arc<RdfPatchFrame>>, Status> {
        self.topics.register_publisher(topic, options)
    }

    /// Subscribes to `topic`, creating it when absent.
    pub(crate) fn subscribe(
        &self,
        topic: &str,
    ) -> Result<
        (
            broadcast::Receiver<Arc<RdfPatchFrame>>,
            Option<RdfPatchOptions>,
        ),
        Status,
    > {
        self.topics.subscribe(topic)
    }
}

impl Default for PatchTopicRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_TOPIC_CAPACITY)
    }
}

/// Checks whether published stream options satisfy a subscriber request.
///
/// Zero or unspecified fields in `requested` are treated as "no
/// constraint", mirroring proto3 default semantics. Constraints:
/// the requested physical and logical types must match when specified,
/// the requested version and table sizes are upper bounds the published
/// stream must fit under, and the published stream must not use RDF-star
/// or generalized statements unless the request allows them.
///
/// # Errors
///
/// Returns a human-readable mismatch description; the service maps it to
/// `INVALID_ARGUMENT` per the `grpc.proto` contract.
pub(crate) fn check_requested_options(
    requested: &RdfStreamOptions,
    published: &RdfStreamOptions,
) -> Result<(), String> {
    if requested.physical_type != 0 && requested.physical_type != published.physical_type {
        return Err(format!(
            "requested physical type {} does not match published physical type {}",
            requested.physical_type, published.physical_type
        ));
    }
    if requested.logical_type != 0 && requested.logical_type != published.logical_type {
        return Err(format!(
            "requested logical type {} does not match published logical type {}",
            requested.logical_type, published.logical_type
        ));
    }
    check_shared_option_bounds(
        requested.version,
        published.version,
        requested.rdf_star,
        published.rdf_star,
        requested.generalized_statements,
        published.generalized_statements,
        [
            (
                "name",
                requested.max_name_table_size,
                published.max_name_table_size,
            ),
            (
                "prefix",
                requested.max_prefix_table_size,
                published.max_prefix_table_size,
            ),
            (
                "datatype",
                requested.max_datatype_table_size,
                published.max_datatype_table_size,
            ),
        ],
    )
}

/// Checks whether published patch options satisfy a subscriber request.
///
/// Same proto3 zero-means-no-constraint semantics as
/// [`check_requested_options`], over the patch option fields: the
/// requested statement and stream types must match when specified, the
/// requested version and table sizes are upper bounds, and RDF-star or
/// generalized statements must be allowed by the request when published.
///
/// # Errors
///
/// Returns a human-readable mismatch description; the service maps it to
/// `INVALID_ARGUMENT`.
pub(crate) fn check_requested_patch_options(
    requested: &RdfPatchOptions,
    published: &RdfPatchOptions,
) -> Result<(), String> {
    if requested.statement_type != 0 && requested.statement_type != published.statement_type {
        return Err(format!(
            "requested statement type {} does not match published statement type {}",
            requested.statement_type, published.statement_type
        ));
    }
    if requested.stream_type != 0 && requested.stream_type != published.stream_type {
        return Err(format!(
            "requested stream type {} does not match published stream type {}",
            requested.stream_type, published.stream_type
        ));
    }
    check_shared_option_bounds(
        requested.version,
        published.version,
        requested.rdf_star,
        published.rdf_star,
        requested.generalized_statements,
        published.generalized_statements,
        [
            (
                "name",
                requested.max_name_table_size,
                published.max_name_table_size,
            ),
            (
                "prefix",
                requested.max_prefix_table_size,
                published.max_prefix_table_size,
            ),
            (
                "datatype",
                requested.max_datatype_table_size,
                published.max_datatype_table_size,
            ),
        ],
    )
}

/// Checks the option bounds shared by RDF stream and patch requests.
fn check_shared_option_bounds(
    requested_version: u32,
    published_version: u32,
    requested_rdf_star: bool,
    published_rdf_star: bool,
    requested_generalized: bool,
    published_generalized: bool,
    tables: [(&str, u32, u32); 3],
) -> Result<(), String> {
    if requested_version != 0 && requested_version < published_version {
        return Err(format!(
            "requested protocol version {requested_version} is below the published version \
             {published_version}"
        ));
    }
    if published_rdf_star && !requested_rdf_star {
        return Err("published stream uses RDF-star, which the request does not allow".into());
    }
    if published_generalized && !requested_generalized {
        return Err(
            "published stream uses generalized statements, which the request does not allow".into(),
        );
    }
    for (label, requested_size, published_size) in tables {
        if requested_size != 0 && requested_size < published_size {
            return Err(format!(
                "requested {label} table size {requested_size} is below the published size \
                 {published_size}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_shares_one_frame_allocation() {
        let registry = TopicRegistry::default();
        let options = RdfStreamOptions::default();
        let sender = registry.register_publisher("t", &options).unwrap();
        let (mut first, _) = registry.subscribe("t").unwrap();
        let (mut second, _) = registry.subscribe("t").unwrap();
        let frame = Arc::new(RdfStreamFrame::default());
        sender.send(Arc::clone(&frame)).expect("live subscribers");
        let got_first = first.try_recv().expect("first subscriber");
        let got_second = second.try_recv().expect("second subscriber");
        assert!(
            Arc::ptr_eq(&got_first, &got_second) && Arc::ptr_eq(&got_first, &frame),
            "fan-out must bump Arc, not clone the prost frame"
        );
    }

    #[test]
    fn fresh_topic_names_cannot_grow_the_registry_without_bound() {
        let registry = TopicRegistry::with_max_topics(4, 8);
        let mut held = Vec::new();
        for index in 0..8 {
            held.push(registry.subscribe(&format!("live-{index}")).unwrap());
        }
        let refused = registry.subscribe("one-too-many").unwrap_err();
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);

        // Dropped subscriptions leave dead topics, which are pruned first.
        held.clear();
        for index in 0..1_000 {
            drop(registry.subscribe(&format!("churn-{index}")).unwrap());
        }
        assert!(registry.topic_count() <= 8);

        let oversized = "t".repeat(MAX_TOPIC_NAME_BYTES + 1);
        assert_eq!(
            registry.subscribe(&oversized).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn a_topic_with_a_live_publisher_is_never_pruned() {
        let registry = TopicRegistry::with_max_topics(4, 1);
        let sender = registry
            .register_publisher("busy", &RdfStreamOptions::default())
            .unwrap();
        assert_eq!(
            registry.subscribe("other").unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        drop(sender);
        assert!(registry.subscribe("other").is_ok());
    }
}
