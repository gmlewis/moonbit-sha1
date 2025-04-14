///|
/// This package is based on the Go implementation found here:
/// https://cs.opensource.google/go/go/+/refs/tags/go1.23.0:src/crypto/sha1/sha1_test.go
/// which has the copyright notice:
/// Copyright 2009 The Go Authors. All rights reserved.
/// Use of this source code is governed by a BSD-style
/// license that can be found in the LICENSE file.
struct SHA1Test {
  out : String
  s : Bytes
}

///|
let golden : Array[SHA1Test] = [
  {
    out: "76245dbf96f661bd221046197ab8b9f063f11bad",
    s: b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
  },
  { out: "da39a3ee5e6b4b0d3255bfef95601890afd80709", s: b"" },
  { out: "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", s: b"a" },
  { out: "da23614e02469a0d7c7bd1bdab5c9c474b1904dc", s: b"ab" },
  { out: "a9993e364706816aba3e25717850c26c9cd0d89d", s: b"abc" },
  { out: "81fe8bfe87576c3ecb22426f8e57847382917acf", s: b"abcd" },
  { out: "03de6c570bfe24bfc328ccd7ca46b76eadaf4334", s: b"abcde" },
  { out: "1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", s: b"abcdef" },
  { out: "2fb5e13419fc89246865e7a324f476ec624e8740", s: b"abcdefg" },
  { out: "425af12a0743502b322e93a015bcf868e324d56a", s: b"abcdefgh" },
  { out: "c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", s: b"abcdefghi" },
  { out: "d68c19a0a345b7eab78d5e11e991c026ec60db63", s: b"abcdefghij" },
  {
    out: "ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7",
    s: b"Discard medicine more than two years old.",
  },
  {
    out: "e5dea09392dd886ca63531aaa00571dc07554bb6",
    s: b"He who has a shady past knows that nice guys finish last.",
  },
  {
    out: "45988f7234467b94e3e9494434c96ee3609d8f8f",
    s: b"I wouldn't marry him with a ten foot pole.",
  },
  {
    out: "55dee037eb7460d5a692d1ce11330b260e40c988",
    s: b"Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave",
  },
  {
    out: "b7bc5fb91080c7de6b582ea281f8a396d7c0aee8",
    s: b"The days of the digital watch are numbered.  -Tom Stoppard",
  },
  {
    out: "c3aed9358f7c77f523afe86135f06b95b3999797",
    s: b"Nepal premier won't resign.",
  },
  {
    out: "6e29d302bf6e3a5e4305ff318d983197d6906bb9",
    s: b"For every action there is an equal and opposite government program.",
  },
  {
    out: "597f6a540010f94c15d71806a99a2c8710e747bd",
    s: b"His money is twice tainted: 'taint yours and 'taint mine.",
  },
  {
    out: "6859733b2590a8a091cecf50086febc5ceef1e80",
    s: b"There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
  },
  {
    out: "514b2630ec089b8aee18795fc0cf1f4860cdacad",
    s: b"It's a tiny change to the code and not completely disgusting. - Bob Manchek",
  },
  {
    out: "c5ca0d4a7b6676fc7aa72caa41cc3d5df567ed69",
    s: b"size:  a.out:  bad magic",
  },
  {
    out: "74c51fa9a04eadc8c1bbeaa7fc442f834b90a00a",
    s: b"The major problem is with sendmail.  -Mark Horton",
  },
  {
    out: "0b4c4ce5f52c3ad2821852a8dc00217fa18b8b66",
    s: b"Give me a rock, paper and scissors and I will move the world.  CCFestoon",
  },
  {
    out: "3ae7937dd790315beb0f48330e8642237c61550a",
    s: b"If the enemy is within range, then so are you.",
  },
  {
    out: "410a2b296df92b9a47412b13281df8f830a9f44b",
    s: b"It's well we cannot hear the screams/That we create in others' dreams.",
  },
  {
    out: "841e7c85ca1adcddbdd0187f1289acb5c642f7f5",
    s: b"You remind me of a TV show, but that's all right: I watch it anyway.",
  },
  {
    out: "163173b825d03b952601376b25212df66763e1db",
    s: b"C is as portable as Stonehedge!!",
  },
  {
    out: "32b0377f2687eb88e22106f133c586ab314d5279",
    s: b"Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley",
  },
  {
    out: "0885aaf99b569542fd165fa44e322718f4a984e0",
    s: b"The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule",
  },
  {
    out: "6627d6904d71420b0bf3886ab629623538689f45",
    s: b"How can you write a big system without C++?  -Paul Glick",
  },
]

///|
test "check_sum works properly" {
  for tt in golden {
    let digest = @sha1.Digest::new()
    let b = @io.Slice::new(tt.s.to_array())
    guard digest.write(b) is (_, None)
    let got = digest.check_sum()
    assert_eq!(got, tt.out)
  }
}
