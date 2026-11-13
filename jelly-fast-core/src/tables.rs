// Rust guideline compliant 2026-02-21
//! Bounded Jelly lookup tables for the encoder and the decoder.
//!
//! Jelly compresses IRIs and datatypes through three 1-based lookup tables
//! (prefix, name, datatype). Table identifiers may be reassigned once a
//! table is full; both sides therefore resolve identifiers strictly in row
//! order and never cache resolved strings across entry rows.

use std::collections::HashMap;

use crate::error::{JellyError, JellyResource};

/// One occupied slot of an encoder-side lookup table.
#[derive(Debug)]
struct EncoderSlot {
    /// Interned string stored at this identifier.
    value: String,
    /// Logical clock of the most recent use, for LRU eviction.
    last_used: u64,
    /// Statement row that most recently referenced this identifier.
    ///
    /// A slot stamped with the row currently being encoded must not be
    /// reassigned: the identifier is already destined for that row, and the
    /// wire format has no way to say "one row, one identifier, two values".
    generation: u64,
}

/// A lookup entry the encoder must emit before referencing its identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingEntry {
    /// Identifier to place in the entry row's `id` field.
    ///
    /// Already delta-compressed: `0` means "previous entry id + 1" per the
    /// Jelly conventions for `RdfPrefixEntry`, `RdfNameEntry`, and
    /// `RdfDatatypeEntry`.
    pub wire_id: u32,
    /// String value of the entry.
    pub value: String,
}

/// Encoder-side bounded lookup table with LRU reassignment.
///
/// When the table is full, the least recently used identifier is
/// reassigned to the new value; the caller must emit the returned
/// [`PendingEntry`] row before any statement row that references the
/// identifier (Jelly allows identifier reuse under exactly this rule).
#[derive(Debug)]
pub(crate) struct EncoderTable {
    resource: JellyResource,
    capacity: u32,
    slots: Vec<EncoderSlot>,
    ids: HashMap<String, u32>,
    clock: u64,
    last_emitted_id: u32,
}

impl EncoderTable {
    /// Creates an empty table holding at most `capacity` entries.
    ///
    /// `resource` names the table in the [`JellyError::ResourceLimit`] a
    /// too-small table raises.
    pub(crate) fn new(resource: JellyResource, capacity: u32) -> Self {
        Self {
            resource,
            capacity,
            slots: Vec::new(),
            ids: HashMap::new(),
            clock: 0,
            last_emitted_id: 0,
        }
    }

    /// Interns `value` for statement row `generation`.
    ///
    /// Returns the 1-based identifier and, when the value is new to the
    /// table, the entry row the caller must emit before the row that
    /// references the identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::ResourceLimit`] when the table cannot hold all
    /// the distinct values one statement row needs. Every entry row for a
    /// statement precedes that statement on the wire, so two values sharing
    /// one identifier within a row would collapse to whichever was assigned
    /// last and silently rewrite a term. Jelly's identifier reassignment is
    /// defined *between* rows, not inside one, and there is no encoding for
    /// the inside case — so the encoder fails closed instead of emitting a
    /// stream that decodes to different data.
    ///
    /// Because `clock` is monotonic, the least-recently-used victim carries
    /// the current generation only when *every* slot does; a table at least
    /// as large as the row's distinct-value count is therefore never
    /// refused.
    pub(crate) fn intern(
        &mut self,
        value: &str,
        generation: u64,
    ) -> Result<(u32, Option<PendingEntry>), JellyError> {
        if self.capacity == 0 {
            return Err(JellyError::ResourceLimit {
                resource: self.resource,
                limit: 0,
                observed: 1,
            });
        }
        self.clock += 1;
        if let Some(&id) = self.ids.get(value) {
            let slot = &mut self.slots[(id - 1) as usize];
            slot.last_used = self.clock;
            slot.generation = generation;
            return Ok((id, None));
        }
        let id = if (self.slots.len() as u32) < self.capacity {
            self.slots.push(EncoderSlot {
                value: value.to_owned(),
                last_used: self.clock,
                generation,
            });
            self.slots.len() as u32
        } else {
            // Reassign the least recently used identifier.
            let Some(index) = self
                .slots
                .iter()
                .enumerate()
                .min_by_key(|(_, slot)| slot.last_used)
                .map(|(index, _)| index)
            else {
                return Err(JellyError::ResourceLimit {
                    resource: self.resource,
                    limit: self.capacity,
                    observed: self.capacity.saturating_add(1),
                });
            };
            if self.slots[index].generation == generation {
                return Err(JellyError::ResourceLimit {
                    resource: self.resource,
                    limit: self.capacity,
                    observed: self.capacity.saturating_add(1),
                });
            }
            let evicted = std::mem::replace(
                &mut self.slots[index],
                EncoderSlot {
                    value: value.to_owned(),
                    last_used: self.clock,
                    generation,
                },
            );
            self.ids.remove(&evicted.value);
            (index + 1) as u32
        };
        self.ids.insert(value.to_owned(), id);
        // Entry-row delta convention: id 0 means "previous entry id + 1"
        // (and 1 for the first entry of the stream).
        let wire_id = if id == self.last_emitted_id + 1 {
            0
        } else {
            id
        };
        self.last_emitted_id = id;
        Ok((
            id,
            Some(PendingEntry {
                wire_id,
                value: value.to_owned(),
            }),
        ))
    }
}

/// Highest identifier stored in a decoder table's dense slot vector.
///
/// Identifiers up to this bound live in a vector grown on demand (at most
/// 65,536 slots, about 1.5 MiB); larger ones, which only a table configured
/// far above the defaults (128 / 4,000 / 32) can declare, live in a map. A
/// table therefore never allocates for identifiers that never arrive: a
/// stream declaring `u32::MAX` slots used to reserve about 100 GB up front.
const DENSE_SLOT_LIMIT: u32 = 1 << 16;

/// Decoder-side bounded lookup table.
///
/// Identifiers resolve to the value most recently assigned to them, which
/// implements Jelly's identifier-reassignment rule for free as long as rows
/// are processed strictly in order. Storage grows with the entries that
/// arrive, never with the declared capacity.
#[derive(Debug)]
pub(crate) struct DecoderTable {
    label: &'static str,
    capacity: u32,
    dense: Vec<Option<String>>,
    sparse: HashMap<u32, String>,
    last_assigned_id: u32,
}

impl DecoderTable {
    /// Creates an empty table bounded by the stream's declared `capacity`.
    pub(crate) fn new(label: &'static str, capacity: u32) -> Self {
        Self {
            label,
            capacity,
            dense: Vec::new(),
            sparse: HashMap::new(),
            last_assigned_id: 0,
        }
    }

    fn out_of_range(&self, what: &str, id: u32) -> JellyError {
        JellyError::Lookup(format!(
            "{} {what} {id} is outside the declared table size {}",
            self.label, self.capacity
        ))
    }

    /// Assigns `value` to `wire_id`, applying the id-0 delta convention.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Lookup`] when the resolved identifier is zero
    /// or exceeds the declared table size.
    pub(crate) fn assign(&mut self, wire_id: u32, value: String) -> Result<(), JellyError> {
        let id = if wire_id == 0 {
            self.last_assigned_id.checked_add(1).unwrap_or(0)
        } else {
            wire_id
        };
        if id == 0 || id > self.capacity {
            return Err(self.out_of_range("entry id", id));
        }
        if id <= DENSE_SLOT_LIMIT {
            let index =
                usize::try_from(id - 1).map_err(|_overflow| self.out_of_range("entry id", id))?;
            if self.dense.len() <= index {
                self.dense.resize(index.saturating_add(1), None);
            }
            if let Some(slot) = self.dense.get_mut(index) {
                *slot = Some(value);
            }
        } else {
            self.sparse.insert(id, value);
        }
        self.last_assigned_id = id;
        Ok(())
    }

    /// Resolves `id` to its current value.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Lookup`] when `id` is zero, out of range, or
    /// was never assigned (a lookup miss is a protocol violation and the
    /// decoder fails closed instead of guessing).
    pub(crate) fn get(&self, id: u32) -> Result<&str, JellyError> {
        if id == 0 || id > self.capacity {
            return Err(self.out_of_range("id", id));
        }
        let value = if id <= DENSE_SLOT_LIMIT {
            usize::try_from(id - 1)
                .ok()
                .and_then(|index| self.dense.get(index))
                .and_then(Option::as_deref)
        } else {
            self.sparse.get(&id).map(String::as_str)
        };
        value.ok_or_else(|| {
            JellyError::Lookup(format!(
                "{} id {id} was referenced before being assigned",
                self.label
            ))
        })
    }
}
