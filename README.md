---
author:
- Cyan Ogilvie
title: hash(3) 0.4.0 \| Implementations of hash functions for Tcl
---

## NAME

hash - Tcl hash function extension

## SYNOPSIS

**package require hash** ?0.4.0?

**hash::md5** *data*  
**hash::sha256** *data*  
**hash::sha384** *data*  
**hash::sha512** *data*  
**hash::areion_perm256** *block*  
**hash::areion_perm512** *block*  
**hash::areion256_dm** *block*  
**hash::areion512_dm** *block*  
**hash::areion512_md** *bytes*

## DESCRIPTION

This package provides Tcl bindings for common cryptographic hash
functions including MD5, the SHA-2 family, and the Areion
permutation-based hash function. The SHA-2 hashes return their results
as hex-encoded strings for historical reasons, everything else returns
binary data. For this reason, if the **tomcrypt** package is available
it is a better choice for SHA-2 than using \[binary decode hex\] on the
result of this package’s SHA-2 functions.

The Areion hash is a special purpose hash built entirely on AES
permutations, which have broad hardware instruction support on modern
architectures. Its design is optimised to maximise performance on short
inputs (up to a few kilobytes) and is much faster than MD5 or SHA-2 for
these cases. This package implements accelerated versions for the x86
and aarch64 architectures (with AES-NI and NEON support, respectively),
with a (slow) pure software fallback for other architectures.

## COMMANDS

**hash::md5** *data*  
Computes the MD5 hash of *data* and returns the result as a binary data.

**hash::sha256** *data*  
Computes the SHA-256 hash of *data* and returns the result as a hex
encoded string.

**hash::sha384** *data*  
Computes the SHA-384 hash of *data* and returns the result as a hex
encoded string.

**hash::sha512** *data*  
Computes the SHA-512 hash of *data* and returns the result as a hex
encoded string.

**hash::areion_perm256** *block*  
Applies the Areion-256 permutation to a 32-byte *block* and returns the
result as binary data. The *block* must be exactly 32 bytes long.

**hash::areion_perm512** *block*  
Applies the Areion-512 permutation to a 64-byte *block* and returns the
result as binary data. The *block* must be exactly 64 bytes long.

**hash::areion256_dm** *block*  
Applies the Areion-256 Davies-Meyer construction to a 32-byte *block*
(permutation XOR input) and returns the result as binary data. The
*block* must be exactly 32 bytes long.

**hash::areion512_dm** *block*  
Applies the Areion-512 Davies-Meyer construction to a 64-byte *block*
(permutation XOR input, then truncated to 32 bytes) and returns the
result as binary data. The *block* must be exactly 64 bytes long.

**hash::areion512_md** *bytes*  
Computes the Areion-512 hash using Merkle-Damgård construction (VIL -
Variable Input Length) on arbitrary-length *bytes* and returns a 32-byte
hash as binary data.

## EXAMPLES

``` tcl
package require hash

# MD5 hash
set data [encoding convertto utf-8 "Hello, world!"]
set hash [hash::md5 $data]
puts [binary encode hex $hash]

# SHA-256 hash
set hash [hash::sha256 $data]
puts $hash

# Areion-512 Merkle-Damgård hash (most commonly used)
set data [encoding convertto utf-8 "Hello, world!"]
set hash [hash::areion512_md $data]
puts [binary encode hex $hash]

# Areion permutation on a 32-byte block
set block [string repeat "\x00" 32]
set permuted [hash::areion_perm256 $block]
puts [binary encode hex $permuted]

# Davies-Meyer construction on a 64-byte block
set block [string repeat "\x01" 64]
set dm_hash [hash::areion512_dm $block]
puts [binary encode hex $dm_hash]
```

## BUILDING

This package has no external dependencies other than Tcl.

### From a Release Tarball

Download and extract [the
release](https://github.com/cyanogilvie/hash/releases/download/v0.4.0/hash0.4.0.tar.gz),
then build in the standard TEA way:

``` sh
wget https://github.com/cyanogilvie/hash/releases/download/v0.4.0/hash0.4.0.tar.gz
tar xf hash0.4.0.tar.gz
cd hash0.4.0
./configure
make
sudo make install
```

### From the Git Sources

Fetch [the code](https://github.com/cyanogilvie/hash) and submodules
recursively, then build in the standard autoconf / TEA way:

``` sh
git clone --recurse-submodules https://github.com/cyanogilvie/hash
cd hash
autoconf
./configure
make
sudo make install
```

### In a Docker Build

Build from a specified release version, avoiding layer pollution and
only adding the installed package without documentation to the image,
and strip debug symbols, minimising image size:

``` dockerfile
WORKDIR /tmp/hash
RUN wget https://github.com/cyanogilvie/hash/releases/download/v0.4.0/hash0.4.0.tar.gz -O - | tar xz --strip-components=1 && \
    ./configure; make test install-binaries install-libraries && \
    strip /usr/local/lib/libhash*.so && \
    cd .. && rm -rf hash
```

For any of the build methods you may need to pass
`--with-tcl /path/to/tcl/lib` to `configure` if your Tcl install is
somewhere nonstandard.

## NOTES

- The MD5 algorithm is considered cryptographically broken and should
  not be used for security purposes.
- Areion is designed to be suitable for cryptographic purposes but is
  new and not extensively reviewed.

## LICENSE

This software is provided under the same license as Tcl.

### Third-Party Components

This extension includes several third-party implementations with their
own licenses:

#### MD5 Implementation

The MD5 implementation in `generic/md5.c` and `generic/md5.h` is by **L.
Peter Deutsch** (ghost@aladdin.com).

**Copyright (C) 1999, 2002 Aladdin Enterprises. All rights reserved.**

Licensed under a permissive license that allows free use, modification,
and redistribution for any purpose, including commercial applications,
with these restrictions:

1.  The origin of the software must not be misrepresented
2.  Altered source versions must be plainly marked as such
3.  The license notice may not be removed from any source distribution

#### SHA-2 Implementation

The SHA-256/384/512 implementations in `generic/sha2.c` and
`generic/sha2.h` are by **Aaron D. Gifford**.

**Copyright (c) 2000-2001, Aaron D. Gifford. All rights reserved.**

Licensed under a BSD-style license that allows redistribution and use in
source and binary forms, with or without modification, provided that:

1.  Redistributions of source code retain the copyright notice,
    conditions and disclaimer
2.  Redistributions in binary form reproduce the copyright notice in
    documentation
3.  The name of the copyright holder may not be used to endorse products
    without written permission

#### Areion Implementation

The Areion hash function implementations in `generic/areion_x86.h` and
`generic/areion_neon.h` are based on the reference implementation from
the research paper:

**“Areion: Highly-Efficient Permutations and Its Applications (Extended
Version)”**  
by Takanori Isobe, Ryoma Ito, Fukang Liu, Kazuhiko Minematsu, Motoki
Nakahashi, Kosei Sakamoto, Rentaro Shiba (2023)  
Published in: IACR Transactions on Cryptographic Hardware and Embedded
Systems, 2023  
DOI:
[10.46586/tches.v2023.i2.115-154](https://doi.org/10.46586/tches.v2023.i2.115-154)  
Available at: https://eprint.iacr.org/2023/794

These files are licensed under **Creative Commons Attribution 4.0
International (CC BY 4.0)**:
https://creativecommons.org/licenses/by/4.0/

All third-party components retain their original copyright notices and
license terms as required by their respective licenses.
