// SPDX-License-Identifier: MIT

use crate::{DecodeError, EncodeError, NetlinkHeader};

/// A `NetlinkDeserializable` type can be deserialized from a buffer
pub trait NetlinkDeserializable: Sized {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Deserialize the given buffer into `Self`.
    fn deserialize(
        header: &NetlinkHeader,
        payload: &[u8],
    ) -> Result<Self, Self::Error>;
}

pub trait NetlinkSerializable {
    fn message_type(&self) -> u16;

    /// Return the length of the serialized data.
    ///
    /// Most netlink messages are encoded following a
    /// [TLV](https://en.wikipedia.org/wiki/Type-length-value) scheme
    /// and this library takes advantage of this by pre-allocating
    /// buffers of the appropriate size when serializing messages,
    /// which is why `buffer_len` is needed.
    fn buffer_len(&self) -> usize;

    /// Serialize this types and write the serialized data into the given
    /// buffer. `buffer`'s length is exactly `InnerMessage::buffer_len()`.
    /// It means that if `InnerMessage::buffer_len()` is buggy and does not
    /// return the appropriate length, bad things can happen:
    ///
    /// - if `buffer_len()` returns a value _smaller than the actual data_,
    ///   `emit()` may panics
    /// - if `buffer_len()` returns a value _bigger than the actual data_, the
    ///   buffer will contain garbage
    ///
    /// # Panic
    ///
    /// This method panics if the buffer is not big enough.
    fn serialize(&self, buffer: &mut [u8]);
}

/// A type that implements `TryEmit` can be serialized without panicking.
///
/// This is the fallible counterpart of [`Emitable`]. It is intentionally
/// independent of the legacy traits: implementations must validate their
/// value and return an [`EncodeError`] instead of panicking on invalid input.
///
/// Implementations append to an existing [`Vec<u8>`] so callers can reuse
/// buffers and nested values can be encoded without temporary allocations.
/// Legacy `Emitable` implementations can delegate to `try_emit_into()` and
/// unwrap the result when maintaining the old panicking contract.
pub trait TryEmit {
    /// Append the serialized value to `out`.
    ///
    /// The value is appended at `out.len()`; existing bytes must not be
    /// modified. Implementations must validate the value and return an
    /// [`EncodeError`] instead of panicking on invalid input. On error they
    /// must truncate `out` back to its original length, so a reused buffer is
    /// not left partially written.
    fn try_emit_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError>;

    /// Serialize this value into a newly allocated buffer.
    ///
    /// This is a convenience wrapper around [`Self::try_emit_into`]. If
    /// encoding fails, the partially written buffer is discarded.
    fn try_emit(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        self.try_emit_into(&mut out)?;
        Ok(out)
    }
}

/// Fallible counterpart of [`NetlinkSerializable`].
///
/// Top-level netlink message payloads implement this trait. It provides the
/// message type needed for the netlink header and the fallible byte emission
/// from [`TryEmit`].
pub trait TrySerialize: TryEmit {
    /// Return the netlink message type of this payload.
    fn message_type(&self) -> u16;
}

/// A fallible netlink attribute.
///
/// This trait is independent of [`Nla`](crate::Nla). Implementations append
/// only the attribute *value* to `out`; the generic emitter reserves the
/// attribute header, writes the length, type and flag bits, and adds alignment
/// padding. Implementations must return an [`EncodeError`] instead of panicking
/// on invalid input.
///
/// The legacy `Nla` trait can delegate to these methods with `unwrap()` when
/// maintaining the old panicking contract. The methods are deliberately named
/// differently from their `Nla` counterparts so that both traits can be
/// imported at the same time.
pub trait TryNla {
    /// Append the attribute value to `out`.
    ///
    /// The value is appended at `out.len()` without any NLA header or padding.
    /// Nested attributes should be appended with
    /// [`TryEmit::try_emit_into`]. On error, implementations must truncate
    /// `out` back to its original length.
    fn try_emit_value_into(&self, out: &mut Vec<u8>)
        -> Result<(), EncodeError>;

    /// Return the attribute type, including the flag bits.
    fn nla_type(&self) -> u16;
}

/// A type that implements `Emitable` can be serialized.
pub trait Emitable {
    /// Return the length of the serialized data.
    fn buffer_len(&self) -> usize;

    /// Serialize this types and write the serialized data into the given
    /// buffer.
    ///
    /// # Panic
    ///
    /// This method panic if the buffer is not big enough. You **must** make
    /// sure the buffer is big enough before calling this method. You can
    /// use [`buffer_len()`](trait.Emitable.html#method.buffer_len) to check
    /// how big the storage needs to be.
    fn emit(&self, buffer: &mut [u8]);
}

/// A `Parseable` type can be used to deserialize data from the type `T` for
/// which it is implemented.
pub trait Parseable<T>
where
    Self: Sized,
    T: ?Sized,
{
    /// Deserialize the current type.
    fn parse(buf: &T) -> Result<Self, DecodeError>;
}

/// A `Parseable` type can be used to deserialize data from the type `T` for
/// which it is implemented.
pub trait ParseableParametrized<T, P>
where
    Self: Sized,
    T: ?Sized,
{
    /// Deserialize the current type.
    fn parse_with_param(buf: &T, params: P) -> Result<Self, DecodeError>;
}
