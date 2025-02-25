# gmlewis/sha1
[![check](https://github.com/gmlewis/moonbit-sha1/actions/workflows/check.yml/badge.svg)](https://github.com/gmlewis/moonbit-sha1/actions/workflows/check.yml)

This is a simple sha1 hash algorithm based on Go's implementation:
https://cs.opensource.google/go/go/+/refs/tags/go1.23.0:src/crypto/sha1/sha1.go
which has the copyright notice:

```
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
```

## Status

The code has been updated to support compiler:

```bash
$ moon version --all
moon 0.1.20250212 (cd7bfb6 2025-02-12) ~/.moon/bin/moon
moonc v0.1.20250213+44ecf4dd9 ~/.moon/bin/moonc
moonrun 0.1.20250212 (cd7bfb6 2025-02-12) ~/.moon/bin/moonrun
```

Use `moonup` to manage `moon` compiler versions:
https://github.com/chawyehsu/moonup
