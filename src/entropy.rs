//! Operating-system entropy, routed through exactly one function.
//!
//! Every secret, nonce and blinding value in this client comes from
//! [`fill`]. Deterministic tests construct their inputs directly rather than
//! swapping this source; the Vision padding generator is seeded from here and
//! then produces its own reproducible stream.

use std::fmt;

/// The operating-system entropy source could not produce bytes.
#[derive(Debug)]
pub struct EntropyError(getrandom::Error);

impl fmt::Display for EntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system random generation failed")
    }
}

impl std::error::Error for EntropyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Fills `destination` with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`EntropyError`] when the operating system cannot produce
/// randomness. Callers treat that as fatal to the operation that needed it.
pub fn fill(destination: &mut [u8]) -> Result<(), EntropyError> {
    getrandom::fill(destination).map_err(EntropyError)
}

/// Returns `T` filled from the operating-system CSPRNG.
///
/// # Errors
///
/// Returns [`EntropyError`] as [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N], EntropyError> {
    let mut bytes = [0_u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}

/// Returns a uniformly distributed value below `bound`.
///
/// Rejection sampling keeps the distribution uniform instead of introducing
/// modulo bias, which would make padding lengths measurably non-uniform.
///
/// # Errors
///
/// Returns [`EntropyError`] when a draw cannot be satisfied.
pub fn below(bound: u32) -> Result<u32, EntropyError> {
    if bound == 0 {
        return Ok(0);
    }
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let mut bytes = [0_u8; 4];
        fill(&mut bytes)?;
        let candidate = u32::from_le_bytes(bytes);
        if candidate < limit {
            return Ok(candidate % bound);
        }
    }
}

/// Buffered uniform generator for Vision padding lengths.
///
/// Padding is drawn once per frame. On a bulk downlink that is one operating
/// system call per 8 KiB, which is measurable, so draws come from a fixed-size
/// buffered block that is refilled from [`fill`] on a bounded budget. The
/// distribution is identical to calling [`below`] directly: the acceptance
/// rule is the same rejection sampler.
///
/// State is fixed size, never grows, and is zeroized on drop.
pub struct BlockRng {
    buffer: [u8; BLOCK_BYTES],
    position: usize,
    issued: u64,
}

/// Bytes drawn per refill.
const BLOCK_BYTES: usize = 256;

/// Bytes drawn before reseeding from the operating system. A policy bound, not
/// a cryptographic limit: the source is the OS CSPRNG, and reseeding keeps any
/// single block's exposure short.
const RESEED_AFTER_BYTES: u64 = 1 << 20;

impl BlockRng {
    /// Creates a generator seeded eagerly from the operating system.
    ///
    /// The first block is filled here so that [`BlockRng::below`] never has to
    /// fail on a hot path for reasons the caller could not have handled.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the operating system cannot seed the block.
    pub fn new() -> Result<Self, EntropyError> {
        let mut generator = Self {
            buffer: [0_u8; BLOCK_BYTES],
            position: BLOCK_BYTES,
            issued: 0,
        };
        generator.refill()?;
        Ok(generator)
    }

    /// Returns a uniformly distributed value below `bound`.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] only when a reseed fails.
    pub fn below(&mut self, bound: u32) -> Result<u32, EntropyError> {
        if bound == 0 {
            return Ok(0);
        }
        let limit = u32::MAX - (u32::MAX % bound);
        loop {
            let candidate = u32::from_le_bytes(self.next_four()?);
            if candidate < limit {
                return Ok(candidate % bound);
            }
        }
    }

    fn next_four(&mut self) -> Result<[u8; 4], EntropyError> {
        if self.position + 4 > BLOCK_BYTES {
            self.refill()?;
        }
        let start = self.position;
        self.position += 4;
        let mut value = [0_u8; 4];
        value.copy_from_slice(&self.buffer[start..start + 4]);
        Ok(value)
    }

    fn refill(&mut self) -> Result<(), EntropyError> {
        if self.issued >= RESEED_AFTER_BYTES {
            self.issued = 0;
        }
        self.buffer.fill(0);
        fill(&mut self.buffer)?;
        self.position = 0;
        self.issued = self.issued.saturating_add(BLOCK_BYTES as u64);
        Ok(())
    }
}

impl Drop for BlockRng {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.buffer);
    }
}

impl fmt::Debug for BlockRng {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockRng")
            .field("state", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
