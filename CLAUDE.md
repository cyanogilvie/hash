# TCL Hash Extension Development Guide

## Build Commands
- Build package: `./configure 'CFLAGS=-DPURIFY -Og' --enable-symbols --with-tcl=/usr/local/lib && make`
- Run all tests: `make test`
- Run single test: `make test TESTFLAGS="-file md5.test"` (or any other test file)
- Test with pattern: `make test TESTFLAGS="-match md5-1*"`
- Memory check: `make valgrind`
- Coverage testing: `make coverage`
- Profile-guided optimization: `make pgo`
- Generate ctags: `make tags`
- Clean: `make clean` (must be run when switching from a coverage to a normal build)

## Development Tools
- Debug with vim-gdb: `make vim-gdb`
- Debug core files: `make vim-core`
- Benchmark all: `make benchmark`
- Benchmark specific: `make benchmark BENCHFLAGS="-match hash-md5*"`
- Container testing: `make test-container`
- Container build: `make build-container`
- Container benchmarking: `make benchmark-container`
- Test the ARM architecture implementations using a container: `make test-container DOCKER_ARGS="--platform linux/arm64" TESTFLAGS="..."`

## Benchmarking Framework
- **Comprehensive Suite**: Tests all hash functions with various data sizes
- **Performance Comparison**: Compares against tcllib, tomcrypt, and other crypto libraries
- **Automatic Batch Sizing**: Optimizes timing precision automatically
- **Statistical Analysis**: Uses advanced teabase_bench framework
- **Dependency Management**: Gracefully handles missing optional packages

### Benchmark Categories
- `hash.bench`: Core algorithm performance tests
- `comparison.bench`: Library comparison benchmarks

### Running Specific Benchmarks
```bash
make benchmark                                   # All hash tests
make benchmark BENCHFLAGS="-match comparison-*"  # Library comparisons  
make benchmark BENCHFLAGS="-match md5-*"         # MD5-specific tests
make benchmark BENCHFLAGS="-match sha256-*"      # SHA-256-specific tests
```

## Code Style
- C standard with basic TEA conventions
- Functions: snake_case (e.g., hash_md5, hash_sha256)
- Constants/macros: UPPER_CASE
- Error handling: Return TCL_OK/TCL_ERROR
- Memory management: Use Tcl memory functions
- Binary data: Use Tcl's byte array objects
- Security: Avoid memory leaks, use proper cleanup

## Project Structure
- `generic/`: C source files
- `tests/`: Test files
- `bench/`: Benchmark scripts
- `teabase/`: Advanced build system support
- `tclconfig/`: TEA build configuration
- `doc/hash.md.in`: Documentation source

## Hash Functions Available
- MD5: `hash::md5`
- SHA-256: `hash::sha256`
- SHA-384: `hash::sha384`
- SHA-512: `hash::sha512`

## Testing
All functions are thoroughly tested with known test vectors. The test suite includes:
- Basic functionality tests
- Edge cases
- Performance benchmarks
- Memory leak detection (with valgrind)
