//! `xtls-rprx-vision` traffic framing.
//!
//! The wire image is derived from rust-reality v2.0.1
//! `src/protocol/vless/vision.rs`, which is the implementation this client must
//! interoperate with. Both directions are implemented natively: this client
//! never shells out to, or embeds, another VLESS stack.
//!
//! One frame is
//!
//! ```text
//! [ command: u8 ][ content length: u16 BE ][ padding length: u16 BE ]
//! [ content ][ zero padding ]
//! ```
//!
//! and the very first frame of a stream is prefixed with the 16-byte VLESS user
//! id. A frame, plus its prefix, never exceeds [`FRAME_SIZE`] bytes on the wire.

use crate::entropy::BlockRng;

/// Maximum wire size of one Vision frame, header and padding included.
pub const FRAME_SIZE: usize = 8 * 1024;

const UUID_SIZE: usize = 16;
const HEADER_SIZE: usize = 5;
const LONG_PADDING_THRESHOLD: usize = 900;
const LONG_PADDING_RANGE: u32 = 500;
const LONG_PADDING_TARGET: usize = 900;
const SHORT_PADDING_RANGE: u32 = 256;

/// Command carried by one Vision frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    /// More framed blocks follow.
    Continue = 0,
    /// Framing ends; every later record's plaintext is payload.
    End = 1,
    /// Framing ends, and so does the record layer around it.
    ///
    /// Both this and [`Command::End`] stop framing, and the frame that carries
    /// either is the same shape. What the peer does *after* that frame is not:
    /// after `End` it keeps sealing outer TLS records and only their plaintext
    /// is unframed (`server/vision.rs:1403-1409`, which advances the direction to
    /// `DirectionState::Outer`), while after `Direct` it replaces the TLS writer
    /// for that direction with the socket itself and writes payload bytes
    /// straight out (`server/vision.rs:1411-1417`, then `:1550-1558`). A receiver
    /// that cannot tell the two apart opens raw payload as ciphertext.
    Direct = 2,
}

impl Command {
    fn from_wire(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            _ => Err(DecodeError::UnknownCommand(value)),
        }
    }
}

/// Receiver state after a fragment has been processed.
///
/// This is the *framing* state: what the bytes arriving now mean. It is not the
/// transport state, and [`Command::Direct`] is why the two must be kept apart —
/// a receiver that stops decoding frames here still has to decide whether the
/// record layer around those frames stays open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Frames are still being decoded.
    Framed,
    /// An `End` command was authenticated; every later record's plaintext is
    /// payload, with the outer record layer still in front of it.
    Raw,
    /// A `Direct` command was authenticated at a frame boundary; every later
    /// byte of the socket is payload and there is no record layer left to open.
    Direct,
}

/// Errors from decoding Vision framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The first frame did not carry the negotiated user id.
    UserIdMismatch,
    /// A frame carried an unknown command byte.
    UnknownCommand(u8),
    /// A frame declared more than [`FRAME_SIZE`] bytes.
    FrameTooLarge {
        /// Declared content length.
        content_length: usize,
        /// Declared padding length.
        padding_length: usize,
    },
    /// A caller reused a decoder after a protocol error.
    Failed,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserIdMismatch => formatter.write_str("Vision user id does not match VLESS user"),
            Self::UnknownCommand(command) => {
                write!(formatter, "Vision command {command} is unknown")
            }
            Self::FrameTooLarge {
                content_length,
                padding_length,
            } => write!(
                formatter,
                "Vision frame content {content_length} plus padding {padding_length} exceeds 8 KiB"
            ),
            Self::Failed => formatter.write_str("Vision decoder already failed"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Errors from encoding Vision framing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Content cannot fit one frame.
    ContentTooLarge {
        /// Content the caller offered.
        length: usize,
        /// Largest content a frame can carry now.
        maximum: usize,
    },
    /// A generated padding length cannot be represented on the wire.
    PaddingTooLarge(usize),
    /// The encoder already emitted a terminating command.
    Finished,
    /// Operating-system entropy was unavailable.
    Entropy,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContentTooLarge { length, maximum } => write!(
                formatter,
                "Vision content {length} bytes exceeds the {maximum} byte frame capacity"
            ),
            Self::PaddingTooLarge(length) => {
                write!(formatter, "Vision padding {length} is not representable")
            }
            Self::Finished => formatter.write_str("Vision encoder already finished"),
            Self::Entropy => formatter.write_str("operating-system entropy unavailable"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Complete description of one frame before any byte is written.
///
/// Planning is separate from assembly so a caller can write the frame directly
/// into its final AEAD plaintext region instead of building it and copying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramePlan {
    include_user_id: bool,
    command: Command,
    content_length: u16,
    padding_length: u16,
}

impl FramePlan {
    /// Exact number of wire bytes this frame occupies.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        let prefix = HEADER_SIZE + if self.include_user_id { UUID_SIZE } else { 0 };
        prefix + self.content_length as usize + self.padding_length as usize
    }

    /// Command this frame carries.
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }

    /// Padding byte count chosen for this frame.
    #[must_use]
    pub const fn padding_len(&self) -> usize {
        self.padding_length as usize
    }

    /// Content byte count carried by this frame.
    #[must_use]
    pub const fn content_len(&self) -> usize {
        self.content_length as usize
    }

    /// Whether the frame is prefixed by the user id.
    #[must_use]
    pub const fn carries_user_id(&self) -> bool {
        self.include_user_id
    }
}

/// Stateful Vision frame encoder.
pub struct Encoder {
    user_id: [u8; UUID_SIZE],
    first_frame: bool,
    finished: bool,
    padding: BlockRng,
}

impl Encoder {
    /// Creates an encoder for the VLESS user that negotiated Vision.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::Entropy`] when the padding generator cannot be
    /// seeded from the operating system.
    pub fn new(user_id: [u8; UUID_SIZE]) -> Result<Self, EncodeError> {
        Ok(Self {
            user_id,
            first_frame: true,
            finished: false,
            padding: BlockRng::new().map_err(|_| EncodeError::Entropy)?,
        })
    }

    /// Computes the frame description for `content_length` bytes.
    ///
    /// State is not advanced; call [`Encoder::commit`] once the frame has
    /// actually been written.
    ///
    /// # Errors
    ///
    /// Rejects oversized content, a finished encoder, and entropy failure.
    pub fn plan(
        &mut self,
        content_length: usize,
        command: Command,
        long_padding: bool,
    ) -> Result<FramePlan, EncodeError> {
        let maximum_padding = self.maximum_padding(content_length)?;
        self.plan_capped(content_length, command, long_padding, maximum_padding)
    }

    /// Computes a frame that also fits within `record_budget` wire bytes.
    ///
    /// Returns `Ok(None)` when even a zero-padding frame cannot fit, which
    /// tells the caller to flush and plan against a fresh budget.
    ///
    /// # Errors
    ///
    /// As [`Encoder::plan`].
    pub fn plan_within(
        &mut self,
        content_length: usize,
        command: Command,
        long_padding: bool,
        record_budget: usize,
    ) -> Result<Option<FramePlan>, EncodeError> {
        let maximum_padding = self.maximum_padding(content_length)?;
        let prefix = HEADER_SIZE + usize::from(self.first_frame) * UUID_SIZE;
        let Some(budget) = record_budget
            .checked_sub(prefix)
            .and_then(|budget| budget.checked_sub(content_length))
        else {
            return Ok(None);
        };
        Ok(Some(self.plan_capped(
            content_length,
            command,
            long_padding,
            maximum_padding.min(budget),
        )?))
    }

    /// Writes one planned frame into `output`, which must be exactly
    /// [`FramePlan::wire_len`] bytes and carry exactly the planned content.
    ///
    /// Assembly is infallible because every fallible decision happened during
    /// planning. A length mismatch leaves `output` untouched rather than
    /// writing a partial frame.
    pub fn assemble(&self, plan: &FramePlan, content: &[u8], output: &mut [u8]) {
        if output.len() != plan.wire_len() || content.len() != plan.content_len() {
            return;
        }
        let mut cursor = 0;
        if plan.include_user_id {
            output[cursor..cursor + UUID_SIZE].copy_from_slice(&self.user_id);
            cursor += UUID_SIZE;
        }
        let header = &mut output[cursor..cursor + HEADER_SIZE];
        header[0] = plan.command as u8;
        header[1..3].copy_from_slice(&plan.content_length.to_be_bytes());
        header[3..5].copy_from_slice(&plan.padding_length.to_be_bytes());
        cursor += HEADER_SIZE;
        output[cursor..cursor + content.len()].copy_from_slice(content);
        cursor += content.len();
        output[cursor..].fill(0);
    }

    /// Advances state after a planned frame has been written.
    pub const fn commit(&mut self, plan: &FramePlan) {
        self.first_frame = false;
        self.finished = !matches!(plan.command, Command::Continue);
    }

    /// Largest content one frame can carry right now.
    #[must_use]
    pub const fn max_content(&self) -> usize {
        let uuid_len = if self.first_frame { UUID_SIZE } else { 0 };
        FRAME_SIZE - HEADER_SIZE - uuid_len
    }

    /// Whether this encoder has emitted its terminating command.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    fn maximum_padding(&self, content_length: usize) -> Result<usize, EncodeError> {
        if self.finished {
            return Err(EncodeError::Finished);
        }
        let prefix = HEADER_SIZE + usize::from(self.first_frame) * UUID_SIZE;
        let maximum_content = FRAME_SIZE - prefix;
        if content_length > maximum_content || content_length > usize::from(u16::MAX) {
            return Err(EncodeError::ContentTooLarge {
                length: content_length,
                maximum: maximum_content,
            });
        }
        Ok(maximum_content - content_length)
    }

    fn plan_capped(
        &mut self,
        content_length: usize,
        command: Command,
        long_padding: bool,
        maximum_padding: usize,
    ) -> Result<FramePlan, EncodeError> {
        let padding_length =
            self.choose_padding_length(content_length, long_padding, maximum_padding)?;
        Ok(FramePlan {
            include_user_id: self.first_frame,
            command,
            content_length: u16::try_from(content_length).map_err(|_| {
                EncodeError::ContentTooLarge {
                    length: content_length,
                    maximum: usize::from(u16::MAX),
                }
            })?,
            padding_length: u16::try_from(padding_length)
                .map_err(|_| EncodeError::PaddingTooLarge(padding_length))?,
        })
    }

    fn choose_padding_length(
        &mut self,
        content_length: usize,
        long_padding: bool,
        maximum: usize,
    ) -> Result<usize, EncodeError> {
        let candidate = if content_length < LONG_PADDING_THRESHOLD && long_padding {
            usize::try_from(
                self.padding
                    .below(LONG_PADDING_RANGE)
                    .map_err(|_| EncodeError::Entropy)?,
            )
            .map_err(|_| EncodeError::Entropy)?
                + LONG_PADDING_TARGET
                - content_length
        } else {
            usize::try_from(
                self.padding
                    .below(SHORT_PADDING_RANGE)
                    .map_err(|_| EncodeError::Entropy)?,
            )
            .map_err(|_| EncodeError::Entropy)?
        };
        Ok(candidate.min(maximum))
    }
}

impl std::fmt::Debug for Encoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("vision::Encoder")
            .field("first_frame", &self.first_frame)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

/// Stateful, allocation-light Vision frame decoder.
pub struct Decoder {
    user_id: [u8; UUID_SIZE],
    first_frame: bool,
    uuid_read: usize,
    header: [u8; HEADER_SIZE],
    header_read: usize,
    content_remaining: usize,
    padding_remaining: usize,
    command: Option<Command>,
    mode: Mode,
    failed: bool,
}

impl Decoder {
    /// Creates a decoder for the VLESS user that negotiated Vision.
    #[must_use]
    pub const fn new(user_id: [u8; UUID_SIZE]) -> Self {
        Self {
            user_id,
            first_frame: true,
            uuid_read: 0,
            header: [0; HEADER_SIZE],
            header_read: 0,
            content_remaining: 0,
            padding_remaining: 0,
            command: None,
            mode: Mode::Framed,
            failed: false,
        }
    }

    /// Current framing mode.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Decodes one fragment, replacing the contents of `output`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] and latches the decoder as failed.
    pub fn decode(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<Mode, DecodeError> {
        output.clear();
        self.decode_append(input, output)
    }

    /// Decodes one fragment, appending payload to `output`.
    ///
    /// Header, user id and padding may each be split at any byte boundary.
    /// Once framing has ended the fragment is payload verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] and latches the decoder as failed.
    ///
    /// # Implementation note
    ///
    /// Payload is copied, never borrowed from the input. Callers therefore do
    /// not need a borrow of the same buffer they are writing into, which keeps
    /// the relay's borrow graph simple.
    pub fn decode_append(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<Mode, DecodeError> {
        if self.failed {
            return Err(DecodeError::Failed);
        }
        let result = self.decode_inner(input, output);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn decode_inner(&mut self, input: &[u8], output: &mut Vec<u8>) -> Result<Mode, DecodeError> {
        if self.mode != Mode::Framed {
            output.extend_from_slice(input);
            return Ok(self.mode);
        }
        let mut cursor = 0;
        while cursor < input.len() {
            if self.first_frame && self.uuid_read < UUID_SIZE {
                let count = (input.len() - cursor).min(UUID_SIZE - self.uuid_read);
                let expected = &self.user_id[self.uuid_read..self.uuid_read + count];
                if input[cursor..cursor + count] != *expected {
                    return Err(DecodeError::UserIdMismatch);
                }
                self.uuid_read += count;
                cursor += count;
                continue;
            }
            if self.header_read < HEADER_SIZE {
                let count = (input.len() - cursor).min(HEADER_SIZE - self.header_read);
                self.header[self.header_read..self.header_read + count]
                    .copy_from_slice(&input[cursor..cursor + count]);
                self.header_read += count;
                cursor += count;
                if self.header_read == HEADER_SIZE {
                    self.start_frame()?;
                }
                continue;
            }
            if self.content_remaining > 0 {
                let count = (input.len() - cursor).min(self.content_remaining);
                output.extend_from_slice(&input[cursor..cursor + count]);
                self.content_remaining -= count;
                cursor += count;
                continue;
            }
            if self.padding_remaining > 0 {
                let count = (input.len() - cursor).min(self.padding_remaining);
                self.padding_remaining -= count;
                cursor += count;
                continue;
            }
            self.finish_frame();
            if self.mode != Mode::Framed {
                output.extend_from_slice(&input[cursor..]);
                return Ok(self.mode);
            }
        }
        if self.frame_complete() {
            self.finish_frame();
        }
        Ok(self.mode)
    }

    fn start_frame(&mut self) -> Result<(), DecodeError> {
        let command = Command::from_wire(self.header[0])?;
        let content_length = usize::from(u16::from_be_bytes([self.header[1], self.header[2]]));
        let padding_length = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
        let prefix = HEADER_SIZE + usize::from(self.first_frame) * UUID_SIZE;
        let wire_length = prefix
            .checked_add(content_length)
            .and_then(|length| length.checked_add(padding_length))
            .ok_or(DecodeError::FrameTooLarge {
                content_length,
                padding_length,
            })?;
        if wire_length > FRAME_SIZE {
            return Err(DecodeError::FrameTooLarge {
                content_length,
                padding_length,
            });
        }
        self.command = Some(command);
        self.content_remaining = content_length;
        self.padding_remaining = padding_length;
        Ok(())
    }

    const fn frame_complete(&self) -> bool {
        self.header_read == HEADER_SIZE
            && self.content_remaining == 0
            && self.padding_remaining == 0
            && self.command.is_some()
    }

    fn finish_frame(&mut self) {
        let Some(command) = self.command.take() else {
            return;
        };
        self.mode = match command {
            Command::Continue => Mode::Framed,
            Command::End => Mode::Raw,
            Command::Direct => Mode::Direct,
        };
        self.first_frame = false;
        self.header_read = 0;
        self.header.fill(0);
    }
}

impl std::fmt::Debug for Decoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("vision::Decoder")
            .field("mode", &self.mode)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Decoder, EncodeError, Encoder, FRAME_SIZE, Mode};

    const USER: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    fn encoder() -> Encoder {
        Encoder::new(USER).expect("system entropy must be available")
    }

    #[test]
    fn first_frame_carries_the_user_id_and_round_trips() {
        let mut encoder = encoder();
        let plan = encoder
            .plan(5, Command::Continue, false)
            .expect("small frame must plan");
        assert!(plan.carries_user_id());
        assert_eq!(plan.wire_len(), 5 + 5 + 16 + plan.padding_len());
        let mut wire = vec![0_u8; plan.wire_len()];
        encoder.assemble(&plan, b"hello", &mut wire);
        encoder.commit(&plan);
        assert_eq!(&wire[..16], &USER);
        assert_eq!(wire[16], 0);

        let mut decoder = Decoder::new(USER);
        let mut output = Vec::new();
        assert_eq!(
            decoder.decode(&wire, &mut output).expect("must decode"),
            Mode::Framed
        );
        assert_eq!(output, b"hello");
    }

    /// Long padding pushes `content + padding` into `[900, 1400)`: the
    /// candidate is `below(500) + 900 - content`, so a 10-byte payload pads to
    /// `890..=1389`. Short padding is a bare `below(256)`.
    #[test]
    fn padding_lengths_stay_in_the_documented_bands() {
        let mut encoder = encoder();
        for _ in 0..2_000 {
            let short = encoder
                .plan(4_000, Command::Continue, false)
                .expect("must plan short");
            assert!(short.padding_len() < 256);

            let long = encoder
                .plan(10, Command::Continue, true)
                .expect("must plan long");
            assert!((890..=1_389).contains(&long.padding_len()));
            assert!((900..=1_399).contains(&(long.padding_len() + 10)));

            let tiny = encoder
                .plan(1_000, Command::Continue, true)
                .expect("must not long-pad past the threshold");
            assert!(tiny.padding_len() < 256);
        }
    }

    #[test]
    fn long_padding_target_holds_at_the_smallest_content() {
        let mut encoder = encoder();
        let plan = encoder
            .plan(0, Command::Continue, true)
            .expect("empty frame must plan");
        assert!((900..1_400).contains(&plan.padding_len()));
        assert!(plan.wire_len() <= FRAME_SIZE);
    }

    #[test]
    fn frame_size_is_the_hard_wire_bound() {
        let mut encoder = encoder();
        assert_eq!(encoder.max_content(), FRAME_SIZE - 5 - 16);
        assert_eq!(
            encoder.plan(FRAME_SIZE - 5 - 16 + 1, Command::Continue, false),
            Err(EncodeError::ContentTooLarge {
                length: FRAME_SIZE - 5 - 16 + 1,
                maximum: FRAME_SIZE - 5 - 16
            })
        );
    }

    /// The first frame costs 21 prefix bytes, so a budget below
    /// `21 + content` cannot hold it at all; a budget above it caps the
    /// padding rather than refusing the frame.
    #[test]
    fn plan_within_reports_when_the_budget_cannot_fit_a_frame() {
        let mut encoder = encoder();
        for budget in [106, 120] {
            let tight = encoder
                .plan_within(100, Command::Continue, true, budget)
                .expect("planning must succeed");
            assert!(tight.is_none(), "budget {budget} must not fit");
        }

        let exact = encoder
            .plan_within(100, Command::Continue, true, 121)
            .expect("planning must succeed")
            .expect("zero-padding frame must fit");
        assert_eq!(exact.padding_len(), 0);
        assert_eq!(exact.wire_len(), 121);

        // 300 - 21 prefix - 100 content = 179 usable bytes, far below the
        // long-padding band, so the cap must bind.
        let roomy = encoder
            .plan_within(100, Command::Continue, true, 300)
            .expect("planning must succeed")
            .expect("capped frame must fit");
        assert_eq!(roomy.padding_len(), 179);
        assert_eq!(roomy.wire_len(), 300);
    }

    #[test]
    fn terminating_command_ends_framing_for_the_rest_of_the_stream() {
        let mut encoder = encoder();
        let mut wire = Vec::new();
        let mut emit = |encoder: &mut Encoder, content: &[u8], command: Command| {
            let plan = encoder
                .plan(content.len(), command, false)
                .expect("must plan");
            wire.resize(plan.wire_len(), 0);
            encoder.assemble(&plan, content, &mut wire);
            encoder.commit(&plan);
            wire.clone()
        };
        let first = emit(&mut encoder, b"one", Command::Continue);
        let second = emit(&mut encoder, b"two", Command::End);
        let trailer = b"raw tail";

        let mut decoder = Decoder::new(USER);
        let mut output = Vec::new();
        decoder
            .decode(&first, &mut output)
            .expect("first frame must decode");
        assert_eq!(output, b"one");
        decoder
            .decode(&second, &mut output)
            .expect("second frame must decode");
        assert_eq!(output, b"two");
        assert_eq!(decoder.mode(), Mode::Raw);
        decoder
            .decode(trailer, &mut output)
            .expect("trailer must decode");
        assert_eq!(output, trailer);
    }

    /// `Direct` is the transition the node chooses when a nested TLS record ends at
    /// a copy-friendly boundary, and it has to be right to the byte: the content of
    /// the frame that carries it, the frames before it, and the raw bytes that
    /// already arrived *behind* it in the same plaintext all have to come out in
    /// that order. Feeding one buffer that contains all three is the point — a
    /// decoder that handed the tail to the relay before finishing the frame would
    /// still pass a test that decoded each frame on its own.
    #[test]
    fn direct_command_ends_framing_without_reordering_the_bytes_around_it() {
        assert_eq!(
            Command::from_wire(2),
            Ok(Command::Direct),
            "the node's third command value is the one this client stops framing on"
        );

        let mut encoder = encoder();
        let mut wire = Vec::new();
        let mut emit = |encoder: &mut Encoder, content: &[u8], command: Command| {
            let plan = encoder
                .plan(content.len(), command, false)
                .expect("must plan");
            wire.resize(plan.wire_len(), 0);
            encoder.assemble(&plan, content, &mut wire);
            encoder.commit(&plan);
            wire.clone()
        };

        let mut plaintext = emit(&mut encoder, b"first", Command::Continue);
        plaintext.extend(emit(&mut encoder, b"second", Command::Direct));
        let tail = b"raw tail";
        plaintext.extend(tail);

        let mut decoder = Decoder::new(USER);
        let mut output = Vec::new();
        assert_eq!(
            decoder
                .decode(&plaintext, &mut output)
                .expect("one plaintext with a transition inside it must decode"),
            Mode::Direct,
            "the buffer that carries `Direct` is past framing by the time the \
             decoder is done, and reports the transition it actually saw"
        );
        assert_eq!(
            output, b"firstsecondraw tail",
            "framed content, then the tail of the same buffer, nothing duplicated"
        );

        let more = b"and then the stream keeps going";
        assert_eq!(
            decoder
                .decode(more, &mut output)
                .expect("raw bytes never stop being payload"),
            Mode::Direct
        );
        assert_eq!(
            output, more,
            "and what follows the transition is appended, not re-framed — `decode` \
             reports the bytes of the fragment it was handed"
        );
    }

    /// The two terminating commands mean the same thing about *frames* and
    /// opposite things about the *record layer*, so a decoder that reported them
    /// identically would leave its caller no way to tell that the difference
    /// exists: `End` keeps outer TLS records sealed (`server/vision.rs:1403-1409`),
    /// `Direct` abandons them (`:1411-1417` with `:1550-1558`).
    #[test]
    fn end_and_direct_are_the_same_framing_and_different_transitions() {
        let emitted = |command: Command| {
            let mut encoder = encoder();
            let plan = encoder
                .plan(3, command, false)
                .expect("small frame must plan");
            let mut wire = vec![0_u8; plan.wire_len()];
            encoder.assemble(&plan, b"abc", &mut wire);
            encoder.commit(&plan);
            wire
        };

        let mut output = Vec::new();
        let mut ended = Decoder::new(USER);
        assert_eq!(
            ended
                .decode(&emitted(Command::End), &mut output)
                .expect("end"),
            Mode::Raw
        );
        let mut direct = Decoder::new(USER);
        assert_eq!(
            direct
                .decode(&emitted(Command::Direct), &mut output)
                .expect("direct"),
            Mode::Direct
        );
        assert_eq!(ended.mode(), Mode::Raw);
        assert_ne!(
            ended.mode(),
            direct.mode(),
            "one of these keeps the record layer and one does not"
        );
    }

    #[test]
    fn round_trips_a_multi_kibibyte_stream_across_arbitrary_fragment_sizes() {
        let pattern: Vec<u8> = (0..=250_u8).collect();
        let payload: Vec<u8> = pattern.iter().copied().cycle().take(40_000).collect();
        let mut encoder = encoder();
        let mut wire = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + 6_000).min(payload.len());
            let chunk = &payload[offset..end];
            let last = end == payload.len();
            let plan = encoder
                .plan(
                    chunk.len(),
                    if last {
                        Command::End
                    } else {
                        Command::Continue
                    },
                    true,
                )
                .expect("6 KiB chunk must plan");
            let start = wire.len();
            wire.resize(start + plan.wire_len(), 0);
            encoder.assemble(&plan, chunk, &mut wire[start..]);
            encoder.commit(&plan);
            offset = end;
        }

        let mut decoder = Decoder::new(USER);
        let mut output = Vec::new();
        for piece in wire.chunks(97) {
            decoder
                .decode_append(piece, &mut output)
                .expect("fragment must decode");
        }
        assert_eq!(output, payload);
    }

    #[test]
    fn wrong_user_id_is_rejected_and_latches() {
        let mut encoder = encoder();
        let plan = encoder
            .plan(1, Command::Continue, false)
            .expect("must plan");
        let mut wire = vec![0_u8; plan.wire_len()];
        encoder.assemble(&plan, b"x", &mut wire);

        let mut decoder = Decoder::new([0xee; 16]);
        let mut output = Vec::new();
        assert!(decoder.decode(&wire, &mut output).is_err());
        assert!(
            decoder
                .decode(&wire, &mut output)
                .is_err_and(|error| error == super::DecodeError::Failed)
        );
    }

    /// A decoder only accepts framing after the user id, so malformed frames
    /// are tested behind a real prefix rather than being mistaken for a
    /// `UserIdMismatch`.
    #[test]
    fn oversized_and_unknown_frames_are_rejected_without_panicking() {
        let mut output = Vec::new();

        let mut decoder = Decoder::new(USER);
        let mut oversized = USER.to_vec();
        oversized.extend_from_slice(&[0, 0xff, 0xff, 0xff, 0xff]);
        assert!(
            decoder
                .decode(&oversized, &mut output)
                .is_err_and(|error| matches!(error, super::DecodeError::FrameTooLarge { .. }))
        );

        let mut decoder = Decoder::new(USER);
        let mut unknown = USER.to_vec();
        unknown.extend_from_slice(&[9, 0, 1, 0, 0, b'a']);
        assert!(
            decoder
                .decode(&unknown, &mut output)
                .is_err_and(|error| matches!(error, super::DecodeError::UnknownCommand(9)))
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x51a7_d31b_u32;
        for length in 0..1_500 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state.to_le_bytes()[0];
            }
            let mut decoder = Decoder::new(USER);
            let mut output = Vec::new();
            let _ = decoder.decode(&input, &mut output);
            assert!(output.len() <= input.len() + 16);
        }
    }

    #[test]
    fn assemble_leaves_output_untouched_on_length_mismatch() {
        let mut encoder = encoder();
        let plan = encoder
            .plan(3, Command::Continue, false)
            .expect("must plan");
        let mut wire = vec![0xab_u8; plan.wire_len() + 1];
        encoder.assemble(&plan, b"abc", &mut wire);
        assert!(wire.iter().all(|byte| *byte == 0xab));
    }
}
