///|
/// This package is based on the Go implementation found here:
/// https://cs.opensource.google/go/go/+/refs/tags/go1.23.0:src/crypto/sha1/sha1.go
/// which has the copyright notice:
/// Copyright 2009 The Go Authors. All rights reserved.
/// Use of this source code is governed by a BSD-style
/// license that can be found in the LICENSE file.

// The size of a sha1 checksum in bytes.
let size = 20

///|
/// The blocksize of sha1 in bytes.
let block_size = 64

///|
let chunk = 64

///|
let init0 = 0x67452301U

///|
let init1 = 0xEFCDAB89U

///|
let init2 = 0x98BADCFEU

///|
let init3 = 0x10325476U

///|
let init4 = 0xC3D2E1F0U

///|
/// `Digest` represents the partial evaluation of a checksum.
struct Digest {
  h : FixedArray[UInt] // 5
  x : FixedArray[Byte] // chunk
  mut nx : Int
  mut len : UInt64
}

///|
/// `Digest::new` returns a new, reset Digest, ready to sum.
pub fn Digest::new() -> Digest {
  {
    h: FixedArray::from_array([init0, init1, init2, init3, init4]),
    x: FixedArray::make(chunk, b'\x00'),
    nx: 0,
    len: 0,
  }
}

///|
/// `check_sum` returns the final sha1sum as a hex string.
pub fn check_sum(self : Digest) -> String {
  let digest = self.sum()
  let result = @buffer.new(size_hint=2 * size)
  for b in digest {
    result.write_char(to_hex((b.to_int() >> 4) & 0xf))
    result.write_char(to_hex(b.to_int() & 0xf))
  }
  result.contents().to_unchecked_string()
}

///|
/// `sum` returns the final sha1sum as a `FixedArray[Byte]`.
fn sum(self : Digest) -> FixedArray[Byte] {
  // Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
  let tmp = FixedArray::make(64 + 8, b'\x00')
  tmp[0] = b'\x80'
  let t = if self.len % 64 < 56 {
    (56UL - self.len % 64).to_int()
  } else {
    (64UL + 56UL - self.len % 64).to_int()
  }

  // Length in bits.
  let len = self.len << 3
  be_put_uint64(tmp, t, len) // append length in bits
  for i = 0; i < t + 8; i = i + 1 {
    guard self.write_byte(tmp[i]) is None
  }

  // The previous write ensures that a whole number of
  // blocks (i.e. a multiple of 64 bytes) have been hashed.
  if self.nx != 0 {
    panic()
  }

  // Generate digest
  let digest = FixedArray::make(size, b'\x00')
  be_put_uint32(digest, 0, self.h[0])
  be_put_uint32(digest, 4, self.h[1])
  be_put_uint32(digest, 8, self.h[2])
  be_put_uint32(digest, 12, self.h[3])
  be_put_uint32(digest, 16, self.h[4])
  digest
}

///|
/// `reset` resets a digest for re-use.
pub fn reset(self : Digest) -> Unit {
  self.h[0] = init0
  self.h[1] = init1
  self.h[2] = init2
  self.h[3] = init3
  self.h[4] = init4
  self.nx = 0
  self.len = 0
}

///|
let _trait : &@io.Writer = Digest::new()

///|
/// `write` writes a slice of bytes to the digest.
pub impl @io.Writer for Digest with write(self, buf) {
  let mut count = 0
  for b in buf {
    guard self.write_byte(b) is None else { break }
    count += 1
  }
  (count, None)
}

///|
/// `write_byte` writes a byte to the digest.
pub impl @io.ByteWriter for Digest with write_byte(self, b) {
  self.len += 1
  self.x[self.nx] = b
  self.nx += 1
  if self.nx == block_size {
    self.block_generic()
    self.nx = 0
  }
  None
}

///|
let _K0 = 0x5A827999U

///|
let _K1 = 0x6ED9EBA1U

///|
let _K2 = 0x8F1BBCDCU

///|
let _K3 = 0xCA62C1D6U

///|
fn block_generic(self : Digest) -> Unit {
  let w = FixedArray::make(16, 0U)

  //
  let p = self.x
  for i = 0; i < 16; i = i + 1 {
    let j = i * 4
    w[i] = (p[j].to_uint() << 24) |
      (p[j + 1].to_uint() << 16) |
      (p[j + 2].to_uint() << 8) |
      p[j + 3].to_uint()
  }
  //
  let mut a = self.h[0]
  let mut b = self.h[1]
  let mut c = self.h[2]
  let mut d = self.h[3]
  let mut e = self.h[4]
  // Each of the four 20-iteration rounds
  // differs only in the computation of f and
  // the choice of K (_K0, _K1, etc).
  for i = 0; i < 16; i = i + 1 {
    let f = (b & c) | (b.lnot() & d)
    let t = rotl(a, 5) + f + e + w[i & 0xf] + _K0
    let tmp = (t, a, rotl(b, 30), c, d)
    a = tmp.0
    b = tmp.1
    c = tmp.2
    d = tmp.3
    e = tmp.4
  }
  for i = 16; i < 20; i = i + 1 {
    let tmp = w[(i - 3) & 0xf] ^
      w[(i - 8) & 0xf] ^
      w[(i - 14) & 0xf] ^
      w[i & 0xf]
    w[i & 0xf] = rotl(tmp, 1)
    let f = (b & c) | (b.lnot() & d)
    let t = rotl(a, 5) + f + e + w[i & 0xf] + _K0
    let tmp = (t, a, rotl(b, 30), c, d)
    a = tmp.0
    b = tmp.1
    c = tmp.2
    d = tmp.3
    e = tmp.4
  }
  for i = 20; i < 40; i = i + 1 {
    let tmp = w[(i - 3) & 0xf] ^
      w[(i - 8) & 0xf] ^
      w[(i - 14) & 0xf] ^
      w[i & 0xf]
    w[i & 0xf] = rotl(tmp, 1)
    let f = b ^ c ^ d
    let t = rotl(a, 5) + f + e + w[i & 0xf] + _K1
    let tmp = (t, a, rotl(b, 30), c, d)
    a = tmp.0
    b = tmp.1
    c = tmp.2
    d = tmp.3
    e = tmp.4
  }
  for i = 40; i < 60; i = i + 1 {
    let tmp = w[(i - 3) & 0xf] ^
      w[(i - 8) & 0xf] ^
      w[(i - 14) & 0xf] ^
      w[i & 0xf]
    w[i & 0xf] = rotl(tmp, 1)
    let f = ((b | c) & d) | (b & c)
    let t = rotl(a, 5) + f + e + w[i & 0xf] + _K2
    let tmp = (t, a, rotl(b, 30), c, d)
    a = tmp.0
    b = tmp.1
    c = tmp.2
    d = tmp.3
    e = tmp.4
  }
  for i = 60; i < 80; i = i + 1 {
    let tmp = w[(i - 3) & 0xf] ^
      w[(i - 8) & 0xf] ^
      w[(i - 14) & 0xf] ^
      w[i & 0xf]
    w[i & 0xf] = rotl(tmp, 1)
    let f = b ^ c ^ d
    let t = rotl(a, 5) + f + e + w[i & 0xf] + _K3
    let tmp = (t, a, rotl(b, 30), c, d)
    a = tmp.0
    b = tmp.1
    c = tmp.2
    d = tmp.3
    e = tmp.4
  }

  // save state
  self.h[0] += a
  self.h[1] += b
  self.h[2] += c
  self.h[3] += d
  self.h[4] += e
}

///|
fn be_put_uint32(b : FixedArray[Byte], offset : Int, value : UInt) -> Unit {
  b[offset + 3] = (value & 0xff).to_byte()
  b[offset + 2] = ((value >> 8) & 0xff).to_byte()
  b[offset + 1] = ((value >> 16) & 0xff).to_byte()
  b[offset] = ((value >> 24) & 0xff).to_byte()
}

///|
fn be_put_uint64(b : FixedArray[Byte], offset : Int, value : UInt64) -> Unit {
  be_put_uint32(b, offset + 4, (value & 0xffffffff).to_uint())
  be_put_uint32(b, offset, ((value >> 32) & 0xffffffff).to_uint())
}

///|
fn rotl(x : UInt, r : Int) -> UInt {
  (x << r) | (x >> (32 - r))
}

///|
fn to_hex(v : Int) -> Char {
  if v < 10 {
    Int::unsafe_to_char(v + b'0'.to_int())
  } else {
    Int::unsafe_to_char(v - 10 + b'a'.to_int())
  }
}
