---
author:
- Cyan Ogilvie
title: hash(3) 0.3.1 \| Implementations of hash functions for Tcl
---

## NAME

hash - Tcl hash function extension

## SYNOPSIS

**package require hash** ?0.3.1?

**hash::md5** *data*  
**hash::sha256** *data*  
**hash::sha384** *data*  
**hash::sha512** *data*

## DESCRIPTION

This package provides Tcl bindings for common cryptographic hash
functions including MD5 and the SHA-2 family.

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
```

## BUILDING

This package has no external dependencies other than Tcl.

### From a Release Tarball

Download and extract [the
release](https://github.com/cyanogilvie/hash/releases/download/v0.3.1/hash0.3.1.tar.gz),
then build in the standard TEA way:

``` sh
wget https://github.com/cyanogilvie/hash/releases/download/v0.3.1/hash0.3.1.tar.gz
tar xf hash0.3.1.tar.gz
cd hash0.3.1
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
RUN wget https://github.com/cyanogilvie/hash/releases/download/v0.3.1/hash0.3.1.tar.gz -O - | tar xz --strip-components=1 && \
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

## LICENSE

This software is provided under the same license as Tcl.
