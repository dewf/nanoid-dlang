# Nano ID for D

> **Note:** This library was machine-ported with **Gemini 4 Neon**.

A tiny, secure, URL-friendly, unique string ID generator for the [D programming language](https://dlang.org/).

This library is a native, D-idiomatic port of the original JavaScript [Nano ID](https://github.com/ai/nanoid) library by Andrey Sitnik.

- **Zero dependencies.** Uses only Phobos, druntime, and native OS cryptographic APIs.
- **Cryptographically secure.** Uses the operating system's CSPRNG with a lock-free, fork-safe thread-local entropy pool.
- **Unbiased distribution.** Uses bitmask and cutoff rejection sampling instead of naive modulo indexing, avoiding modulo bias across all alphabet sizes.
- **Compact & URL-safe.** Uses a 64-symbol alphabet (`A-Za-z0-9_-`), packing 126 bits of entropy into 21 characters (comparable to UUID v4's 122 bits in 36 characters).
- **Idiomatic D.** `@safe`, `-preview=dip1000`-compatible, CTFE-capable `customAlphabet`, full UTF-8/Unicode alphabet support, and `@nogc nothrow` in-place buffer primitives.

```d
import nanoid : nanoid;

string id = nanoid(); // e.g. "V1StGXR8_Z5jdHi6B-myT"
```

## Table of Contents

- [Comparison with UUID v4](#comparison-with-uuid-v4)
- [Security & Correctness](#security--correctness)
- [Installation](#installation)
- [API](#api)
  - [Default URL-Safe IDs](#default-url-safe-ids)
  - [Zero-Allocation & `@nogc` APIs](#zero-allocation--nogc-apis)
  - [Custom Alphabet or Size](#custom-alphabet-or-size)
  - [Custom Random Source](#custom-random-source)
  - [Raw Cryptographic Random Bytes](#raw-cryptographic-random-bytes)
  - [Non-Secure Generator](#non-secure-generator)
  - [Error Handling](#error-handling)
- [Building & Testing](#building--testing)
- [Tools & References](#tools--references)
- [License](#license)

## Comparison with UUID v4

Nano ID provides collision resistance comparable to random-based UUID v4:

- **UUID v4:** 122 random bits across 36 characters (`0-9a-f` plus 4 hyphens).
- **Nano ID:** 126 random bits across 21 characters (`A-Za-z0-9_-`).

You can estimate collision probabilities for custom lengths and alphabets with the [Nano ID Collision Calculator](https://zelark.github.io/nano-id-cc/).

## Security & Correctness

- **OS CSPRNG backends.** Instead of Phobos's non-cryptographic `std.random`, `nanoid` reads entropy directly from the operating system:
  - **Windows:** `BCryptGenRandom` (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`)
  - **macOS / iOS / FreeBSD / OpenBSD / NetBSD / DragonFlyBSD:** `arc4random_buf`
  - **Linux:** `getrandom(2)` (with automatic `/dev/urandom` fallback on `ENOSYS`)
  - **Other POSIX:** `/dev/urandom` (`O_CLOEXEC`)
- **Thread-safe & fork-safe pooling.** Random bytes are buffered in a thread-local (`TLS`) 4 KiB pool, giving lock-free multi-threaded performance. Consumed bytes are scrubbed immediately after use, large requests bypass the pool, and POSIX processes register a `pthread_atfork` child handler to invalidate inherited pool bytes after `fork()`.
- **Uniformity.** Computing `randomByte % alphabet.length` introduces bias whenever `alphabet.length` does not divide `256`. This library uses power-of-two bitmasking when `alphabet.length` is a power of two and unbiased rejection sampling otherwise.
- **Unicode correctness.** ASCII alphabets take a zero-decoding fast path (`1 char == 1 symbol`). Alphabets containing non-ASCII characters (Cyrillic, CJK, emoji, etc.) are decoded as Unicode code points (`dchar`), so `size` always counts symbols rather than UTF-8 bytes and every generated string is guaranteed to be valid UTF-8.

## Installation

Add `nanoid` to your Dub project:

**`dub.sdl`**
```sdl
dependency "nanoid" version="~>0.9.0"
```

**`dub.json`**
```json
"dependencies": {
    "nanoid": "~>0.9.0"
}
```

Or add it from the command line:

```sh
dub add nanoid
```

## API

### Default URL-Safe IDs

By default, `nanoid()` returns a 21-character string drawn from `urlAlphabet` (`A-Za-z0-9_-`).

Because the package is also named `nanoid`, prefer a selective import when calling `nanoid()` directly, or use the `generate` alias with a whole-module import:

```d
import nanoid : nanoid;

string id = nanoid();       // 21 characters (defaultSize)
string shortId = nanoid(10); // 10 characters
string empty = nanoid(0);    // ""
```

```d
import nanoid;

string id = generate();            // 21 characters
string qualified = nanoid.nanoid(); // 21 characters
```

### Zero-Allocation & `@nogc` APIs

When you want to avoid GC allocations, you can generate into a fixed-size stack array or fill an existing buffer in place:

```d
import nanoid : nanoid, nanoidInto, tryNanoidInto;

// Stack-allocated fixed-length ID (zero heap allocations on success)
char[21] fixed = nanoid!21();
char[10] shortFixed = nanoid!10();

// Fill an existing slice in place (throws NanoIdException on OS RNG failure)
char[21] buf;
nanoidInto(buf[]);

// Strict @safe nothrow @nogc variant (returns false on OS RNG failure)
void makeIdNoGc(scope char[] outBuf) @safe nothrow @nogc
{
    bool ok = tryNanoidInto(outBuf);
    assert(ok);
}
```

### Custom Alphabet or Size

`customAlphabet(alphabet, defaultSize = 21)` validates the alphabet and returns a lightweight, immutable-friendly `NanoIdGenerator` struct.

- Alphabets must contain between **1 and 256** Unicode code points (symbols) and valid UTF-8.
- `customAlphabet` is `pure @safe` and **CTFE-compatible**, so generators can be declared `static immutable` or `enum` and shared across threads with zero synchronization.

```d
import nanoid : customAlphabet;

// Compile-time validated, thread-safe generator
static immutable hexId = customAlphabet("0123456789abcdef", 10);

string a = hexId();   // e.g. "4f90d13a42" (10 chars)
string b = hexId(5);  // e.g. "f01a2" (override size per call)
```

Unicode alphabets work seamlessly — `size` counts Unicode symbols, not UTF-8 bytes:

```d
import nanoid : customAlphabet;

auto cyrillicId = customAlphabet("0123456789абвгдеё", 5);
string id = cyrillicId(); // e.g. "8ё56а" (5 Unicode symbols)
```

In-place buffer filling is also available on `NanoIdGenerator`:

```d
import nanoid : customAlphabet;

static immutable digits = customAlphabet("0123456789", 6);

char[6] asciiBuf;
digits.into(asciiBuf[]);        // throws NanoIdException on failure
bool ok = digits.tryInto(asciiBuf[]); // @safe nothrow @nogc (ASCII alphabets only)

// For any alphabet (ASCII or Unicode), fill a dchar[] buffer:
static immutable emojis = customAlphabet("😀🚀🔥✨", 4);
dchar[4] codePoints;
emojis.into(codePoints[]);
bool okUni = emojis.tryInto(codePoints[]); // @safe nothrow @nogc
```

> Note: `into(char[])` requires an ASCII alphabet (throws `NanoIdException` otherwise, and `tryInto(char[])` returns `false`), because multi-byte UTF-8 symbols do not fit 1-to-1 into `char[]`. Use `opCall()` or `into(dchar[])` for Unicode alphabets.

### Custom Random Source

`customRandom(alphabet, defaultSize, rng)` (or `customRandom(alphabet, rng)` using `defaultSize = 21`) lets you supply your own random generator. Three styles are supported automatically:

1. **Any `std.random` uniform RNG (`isUniformRNG`)** — great for deterministic, seeded tests:

```d
import std.random : Mt19937;
import nanoid : customRandom;

auto gen = customRandom("abcdef", 10, Mt19937(42));
string id = gen(); // Deterministic sequence for seed 42
```

2. **A buffer-filling callable `void(ubyte[])`** — zero-allocation custom byte source:

```d
import nanoid : customRandom, urlAlphabet;

auto gen = customRandom(urlAlphabet, 12, (ubyte[] buf) {
    // Fill buf with random bytes from your custom source
    foreach (i, ref b; buf)
        b = cast(ubyte)(i * 31);
});
string id = gen();
```

3. **A byte-returning callable `const(ubyte)[](size_t)`** — matches JavaScript `customRandom`:

```d
import nanoid : customRandom, random, urlAlphabet;

auto gen = customRandom(urlAlphabet, 10, &random);
string id = gen();
```

> Note: The internal sequence of random calls may change across library versions. Do not rely on seeded `customRandom` producing identical IDs across major/minor upgrades.

### Raw Cryptographic Random Bytes

The underlying OS CSPRNG helpers are re-exported directly from `nanoid` (and defined in `nanoid.random`):

```d
import nanoid : random, fillRandom, tryFillRandom;

ubyte[] bytes = random(32); // Allocates 32 secure random bytes

ubyte[16] buf;
fillRandom(buf[]);          // Fills in place; throws NanoIdException on failure
bool ok = tryFillRandom(buf[]); // @safe nothrow @nogc
```

### Non-Secure Generator

If you do not need cryptographic unpredictability, `nanoid.nonsecure` provides a non-secure generator backed by Phobos's thread-local `std.random.rndGen`:

```d
import nanoid.nonsecure : nanoid, customAlphabet;

string id = nanoid();
auto gen = customAlphabet("0123456789abcdef", 10);
string token = gen();
```

> **Security Warning:** IDs generated by `nanoid.nonsecure` are predictable and must **not** be used for session tokens, secrets, password resets, or any security-sensitive identifier.

### Error Handling

Invalid configuration or OS CSPRNG failures throw `NanoIdException` (a subclass of `Exception`):

- Empty alphabet (`""`)
- Alphabet exceeding 256 Unicode symbols (in secure `customAlphabet` / `customRandom`)
- Invalid UTF-8 in an alphabet string
- Calling `into(char[])` on a generator with a non-ASCII alphabet
- Custom byte-returning callback returning an empty slice
- Operating system CSPRNG failure

## Building & Testing

Run the full unit test suite (including uniformity, edge-case, Unicode, error-recovery, and multi-threaded collision tests):

```sh
dub test
```

Test with LDC:

```sh
dub test --compiler=ldc2
```

Build the release library:

```sh
dub build --build=release
```

## Tools & References

- [Original JavaScript Nano ID](https://github.com/ai/nanoid)
- [Nano ID Collision Probability Calculator](https://zelark.github.io/nano-id-cc/)
- [`nanoid-dictionary`](https://github.com/CyberAP/nanoid-dictionary) — collection of popular custom alphabets

## License

MIT License — see [LICENSE](LICENSE).
