# DERO C-Miner

A mining client for the DERO blockchain, written in C.

## Features

- **Multi-threaded Mining** — Configurable thread count (1-64) for maximum CPU utilization
- **CPU Affinity** — Optional core pinning for consistent performance and reduced context switching
- **Hardware Optimization** — Runtime CPU detection with SSE4.1 SIMD support for Salsa20

## Quick Start

### Requirements

- GCC compiler
- OpenSSL dev libraries (`libssl-dev`)
- cJSON (`libcjson-dev`)
- GMP (`libgmp-dev`)
- Linux with POSIX threads

### Build

```bash
make clean && make
```

### Run

```bash
./cminer -n pool.example.com:10100 -w dero1qyf5nzqyf5nzqyf5nzqyf5nz... -t 8 -a
```

**Arguments:**
- `-n <node>` — Mining pool address (required)
- `-w <wallet>` — DERO wallet address (required)
- `-t <threads>` — Worker threads (default: 1, max: 64)
- `-a` — Enable CPU affinity binding (optional)

## Performance Optimizations

### Automatic CPU Detection
On startup, the miner detects and displays which implementation will be used:
```
Salsa20: Using SSE4.1-optimized implementation
```
Falls back to portable C implementation on systems without SSE4.1 support.

## Mining Algorithm

**AstroBWT v3** — Employs libdivsufsort for fast suffix array construction.

## Dependencies

| Library  | Version | Purpose                                             |
|----------|---------|-----------------------------------------------------|
| OpenSSL  | Any     | TLS/SSL for secure communication and hash functions |
| cJSON    | Any     | JSON parsing                                        |
| GMP      | Any     | Arbitrary precision arithmetic for PoW verification |
| Pthreads | POSIX   | Multi-threading support                             |

## Compatibility

- **OS:** Linux (x86-64, ARM64)
- **Compiler:** GCC
