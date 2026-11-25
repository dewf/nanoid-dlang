/++
    A tiny, secure, URL-friendly, unique string ID generator for D.

    D port of $(LINK2 https://github.com/ai/nanoid, Nano ID).

    Examples:
    ---
    import nanoid : nanoid, customAlphabet, customRandom, urlAlphabet;

    // Default 21-character URL-safe ID (126 bits of entropy)
    string id = nanoid();

    // Custom length
    string shortId = nanoid(10);

    // Zero-allocation stack-allocated ID
    char[21] fixedId = nanoid!21();

    // Custom alphabet (CTFE-compatible and thread-safe)
    static immutable hexId = customAlphabet("0123456789abcdef", 10);
    string token = hexId();
    ---
 +/
module nanoid;

import std.array : appender;
import std.exception : assumeUnique;
import std.random : isUniformRNG, uniform;
import std.utf : decode, encode, UTFException;

public import nanoid.random : fillRandom, NanoIdException, random, tryFillRandom;
import nanoid.random : tryFillPooledRandom;

/// Default Nano ID length (21 symbols from `urlAlphabet`, ~126 bits of entropy).
enum size_t defaultSize = 21;

/// URL-friendly 64-character alphabet (`A-Za-z0-9_-`).
enum string urlAlphabet = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static assert(urlAlphabet.length == 64);

/// Maximum number of symbols allowed in a byte-indexed secure alphabet.
enum size_t maxAlphabetSize = 256;

// ---------------------------------------------------------------------------
// Core URL-safe Nano ID functions
// ---------------------------------------------------------------------------

/++
    Fills `buffer` in place with a cryptographically secure URL-safe Nano ID.

    This is the `@nogc nothrow` primitive underlying `nanoidInto` and `nanoid`.

    Params:
        buffer = Destination slice to fill with characters from `urlAlphabet`.

    Returns:
        `true` on success, or `false` if the OS CSPRNG failed.
 +/
bool tryNanoidInto(scope char[] buffer) @trusted nothrow @nogc
{
    if (buffer.length == 0)
        return true;

    if (!tryFillPooledRandom(cast(ubyte[]) buffer))
    {
        buffer[] = 0;
        return false;
    }

    // urlAlphabet has 64 ASCII characters (a power of two), so masking each
    // random byte with 63 maps 0..255 uniformly onto 0..63 with zero bias.
    foreach (ref char c; buffer)
        c = urlAlphabet[cast(ubyte) c & 63];

    return true;
}

/++
    Fills `buffer` in place with a cryptographically secure URL-safe Nano ID.

    Performs zero heap allocations on success.

    Params:
        buffer = Destination slice to fill with characters from `urlAlphabet`.

    Returns:
        The filled `buffer` slice.

    Throws:
        `NanoIdException` if the OS CSPRNG fails.
 +/
char[] nanoidInto(return scope char[] buffer) @safe
{
    if (!tryNanoidInto(buffer))
        throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");
    return buffer;
}

/++
    Generates a cryptographically secure, URL-friendly Nano ID string.

    By default, generates a 21-character ID with collision resistance
    comparable to UUID v4.

    Params:
        size = Number of characters in the generated ID (default: 21).

    Returns:
        A newly allocated `string` of length `size`.

    Throws:
        `NanoIdException` if the OS CSPRNG fails.
 +/
string nanoid(size_t size = defaultSize) @safe
{
    if (size == 0)
        return "";

    auto buffer = new char[size];
    nanoidInto(buffer);
    return () @trusted { return assumeUnique(buffer); }();
}

/++
    Generates a stack-allocated, fixed-length URL-friendly Nano ID.

    Performs zero heap allocations on success.

    Params:
        size = Compile-time number of characters in the generated ID.

    Returns:
        A `char[size]` static array containing characters from `urlAlphabet`.

    Throws:
        `NanoIdException` if the OS CSPRNG fails.
 +/
char[size] nanoid(size_t size)() @safe
{
    char[size] buffer;
    static if (size > 0)
        nanoidInto(buffer[]);
    return buffer;
}

/++
    Convenience alias for `nanoid`.

    Useful with non-selective `import nanoid;` where the bare identifier
    `nanoid` refers to the package itself:
    ---
    import nanoid;
    string id = generate();
    string shortId = nanoid.generate(10);
    ---
 +/
alias generate = nanoid;

// ---------------------------------------------------------------------------
// Alphabet parsing and bias-free math helpers
// ---------------------------------------------------------------------------

package(nanoid) bool isPureAscii(const(char)[] s) pure nothrow @safe @nogc
{
    foreach (char c; s)
    {
        if (cast(ubyte) c >= 0x80)
            return false;
    }
    return true;
}

private uint computeMask(size_t alphabetLen) pure nothrow @safe @nogc
{
    // Smallest (2^k - 1) >= (alphabetLen - 1) for alphabetLen in 1..256.
    uint m = cast(uint)(alphabetLen - 1);
    m |= m >> 1;
    m |= m >> 2;
    m |= m >> 4;
    return m;
}

private size_t computeStep(size_t count, size_t acceptedPerWindow, size_t windowSize) pure nothrow @safe @nogc
{
    // Request ~1.6x (8/5) the expected number of bytes to minimize refill calls
    // during rejection sampling, computed in integer arithmetic without overflow.
    immutable size_t numFactor = 8 * windowSize;
    immutable size_t denom = 5 * acceptedPerWindow;
    if (count > (size_t.max - denom) / numFactor)
        return size_t.max;
    immutable size_t step = (count * numFactor + denom - 1) / denom;
    return step < count ? count : step;
}

private struct ParsedAlphabet
{
    string ascii;
    dstring unicode;
    size_t length;
    uint mask;
    uint safeByteCutoff;
    bool isAscii;

    bool isPowerOfTwo() const pure nothrow @safe @nogc
    {
        return safeByteCutoff == 256;
    }

    static ParsedAlphabet parse(string alphabet) pure @safe
    {
        if (alphabet.length == 0)
            throw new NanoIdException("Alphabet must not be empty.");

        if (isPureAscii(alphabet))
        {
            if (alphabet.length > maxAlphabetSize)
                throw new NanoIdException("Alphabet must contain at most 256 symbols.");

            ParsedAlphabet result;
            result.ascii = alphabet;
            result.length = alphabet.length;
            result.mask = computeMask(alphabet.length);
            result.safeByteCutoff = cast(uint)(256 - (256 % alphabet.length));
            result.isAscii = true;
            return result;
        }

        dchar[] symbols;
        size_t idx = 0;
        try
        {
            while (idx < alphabet.length)
            {
                dchar c = decode(alphabet, idx);
                if (symbols.length == maxAlphabetSize)
                    throw new NanoIdException("Alphabet must contain at most 256 symbols.");
                symbols ~= c;
            }
        }
        catch (UTFException e)
        {
            throw new NanoIdException("Alphabet contains invalid UTF-8: " ~ e.msg);
        }

        ParsedAlphabet result;
        result.unicode = symbols.idup;
        result.length = result.unicode.length;
        result.mask = computeMask(result.length);
        result.safeByteCutoff = cast(uint)(256 - (256 % result.length));
        result.isAscii = false;
        return result;
    }
}

// ---------------------------------------------------------------------------
// Custom Alphabet Generator (OS CSPRNG)
// ---------------------------------------------------------------------------

/++
    A reusable, thread-safe Nano ID generator bound to a custom alphabet
    and default ID size, backed by the OS CSPRNG.

    Instances are immutable-friendly and can be created at compile time (CTFE):
    ---
    static immutable hexId = customAlphabet("0123456789abcdef", 10);
    string a = hexId();
    string b = hexId(5);
    ---
 +/
struct NanoIdGenerator
{
    private ParsedAlphabet _alphabet;
    private size_t _defaultSize;

    /// Returns the default ID length (in symbols) used when called without arguments.
    size_t defaultSize() const pure nothrow @safe @nogc
    {
        return _defaultSize;
    }

    /// Returns the number of symbols (Unicode code points) in this generator's alphabet.
    size_t alphabetLength() const pure nothrow @safe @nogc
    {
        return _alphabet.length;
    }

    /// Returns `true` if every symbol in the alphabet is single-byte ASCII.
    bool isAscii() const pure nothrow @safe @nogc
    {
        return _alphabet.isAscii;
    }

    /// Generates an ID of length `defaultSize`.
    string opCall() const @safe
    {
        return opCall(_defaultSize);
    }

    /++
        Generates an ID containing `size` symbols from this generator's alphabet.

        For Unicode alphabets, `size` counts Unicode code points (not UTF-8 bytes).
     +/
    string opCall(size_t size) const @safe
    {
        if (size == 0)
            return "";

        if (_alphabet.isAscii)
        {
            auto buffer = new char[size];
            into(buffer);
            return () @trusted { return assumeUnique(buffer); }();
        }

        // Single-symbol Unicode alphabet requires no randomness.
        if (_alphabet.length == 1)
        {
            char[4] encoded;
            immutable size_t unitLen = encode(encoded, _alphabet.unicode[0]);
            auto buffer = new char[unitLen * size];
            for (size_t i = 0; i < buffer.length; i += unitLen)
                buffer[i .. i + unitLen] = encoded[0 .. unitLen];
            return () @trusted { return assumeUnique(buffer); }();
        }

        auto app = appender!string();
        app.reserve(size * 2);

        ubyte[256] rnd;
        size_t written = 0;

        if (_alphabet.isPowerOfTwo)
        {
            immutable uint mask = _alphabet.mask;
            while (written < size)
            {
                immutable size_t remaining = size - written;
                immutable size_t chunk = remaining < rnd.length ? remaining : rnd.length;
                if (!tryFillPooledRandom(rnd[0 .. chunk]))
                    throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");

                foreach (ubyte b; rnd[0 .. chunk])
                    app.put(_alphabet.unicode[b & mask]);

                written += chunk;
            }
        }
        else
        {
            immutable uint mask = _alphabet.mask;
            immutable size_t maskSpan = cast(size_t) mask + 1;
            while (written < size)
            {
                immutable size_t remaining = size - written;
                size_t want = computeStep(remaining, _alphabet.length, maskSpan);
                if (want > rnd.length)
                    want = rnd.length;

                if (!tryFillPooledRandom(rnd[0 .. want]))
                    throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");

                foreach (ubyte b; rnd[0 .. want])
                {
                    immutable uint idx = b & mask;
                    if (idx < _alphabet.length)
                    {
                        app.put(_alphabet.unicode[idx]);
                        if (++written == size)
                            break;
                    }
                }
            }
        }

        return app.data;
    }

    /++
        Fills `buffer` in place with ASCII symbols from this generator's alphabet.

        This is a `@nogc nothrow` operation.

        Returns:
            `true` on success, or `false` if this generator has a non-ASCII
            alphabet or the OS CSPRNG failed.
     +/
    bool tryInto(scope char[] buffer) const @trusted nothrow @nogc
    {
        if (!_alphabet.isAscii)
            return false;

        if (buffer.length == 0)
            return true;

        if (_alphabet.length == 1)
        {
            buffer[] = _alphabet.ascii[0];
            return true;
        }

        if (_alphabet.isPowerOfTwo)
        {
            if (!tryFillPooledRandom(cast(ubyte[]) buffer))
            {
                buffer[] = 0;
                return false;
            }

            immutable uint mask = _alphabet.mask;
            foreach (ref char c; buffer)
                c = _alphabet.ascii[cast(ubyte) c & mask];
            return true;
        }

        ubyte[256] rnd;
        immutable uint mask = _alphabet.mask;
        immutable size_t maskSpan = cast(size_t) mask + 1;
        size_t written = 0;

        while (written < buffer.length)
        {
            immutable size_t remaining = buffer.length - written;
            size_t want = computeStep(remaining, _alphabet.length, maskSpan);
            if (want > rnd.length)
                want = rnd.length;

            if (!tryFillPooledRandom(rnd[0 .. want]))
            {
                buffer[] = 0;
                return false;
            }

            foreach (ubyte b; rnd[0 .. want])
            {
                immutable uint idx = b & mask;
                if (idx < _alphabet.length)
                {
                    buffer[written++] = _alphabet.ascii[idx];
                    if (written == buffer.length)
                        break;
                }
            }
        }

        return true;
    }

    /++
        Fills `buffer` in place with ASCII symbols from this generator's alphabet.

        Throws:
            `NanoIdException` if the alphabet contains non-ASCII characters
            or if the OS CSPRNG fails.
     +/
    char[] into(return scope char[] buffer) const @safe
    {
        if (!_alphabet.isAscii)
            throw new NanoIdException(
                "into(char[]) requires an ASCII alphabet; use into(dchar[]) or opCall() for Unicode alphabets."
            );

        if (!tryInto(buffer))
            throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");

        return buffer;
    }

    /++
        Fills `buffer` in place with Unicode code points (`dchar`) from this
        generator's alphabet. Works for both ASCII and Unicode alphabets.

        This is a `@nogc nothrow` operation.

        Returns:
            `true` on success, or `false` if the OS CSPRNG failed.
     +/
    bool tryInto(scope dchar[] buffer) const @trusted nothrow @nogc
    {
        if (buffer.length == 0)
            return true;

        if (_alphabet.length == 1)
        {
            buffer[] = _alphabet.isAscii ? cast(dchar) _alphabet.ascii[0] : _alphabet.unicode[0];
            return true;
        }

        ubyte[256] rnd;
        immutable uint mask = _alphabet.mask;
        size_t written = 0;

        if (_alphabet.isPowerOfTwo)
        {
            while (written < buffer.length)
            {
                immutable size_t remaining = buffer.length - written;
                immutable size_t chunk = remaining < rnd.length ? remaining : rnd.length;
                if (!tryFillPooledRandom(rnd[0 .. chunk]))
                {
                    buffer[] = 0;
                    return false;
                }

                if (_alphabet.isAscii)
                {
                    foreach (ubyte b; rnd[0 .. chunk])
                        buffer[written++] = cast(dchar) _alphabet.ascii[b & mask];
                }
                else
                {
                    foreach (ubyte b; rnd[0 .. chunk])
                        buffer[written++] = _alphabet.unicode[b & mask];
                }
            }
            return true;
        }

        immutable size_t maskSpan = cast(size_t) mask + 1;
        while (written < buffer.length)
        {
            immutable size_t remaining = buffer.length - written;
            size_t want = computeStep(remaining, _alphabet.length, maskSpan);
            if (want > rnd.length)
                want = rnd.length;

            if (!tryFillPooledRandom(rnd[0 .. want]))
            {
                buffer[] = 0;
                return false;
            }

            foreach (ubyte b; rnd[0 .. want])
            {
                immutable uint idx = b & mask;
                if (idx < _alphabet.length)
                {
                    buffer[written++] = _alphabet.isAscii
                        ? cast(dchar) _alphabet.ascii[idx]
                        : _alphabet.unicode[idx];
                    if (written == buffer.length)
                        break;
                }
            }
        }

        return true;
    }

    /++
        Fills `buffer` in place with Unicode code points (`dchar`) from this
        generator's alphabet.

        Throws:
            `NanoIdException` if the OS CSPRNG fails.
     +/
    dchar[] into(return scope dchar[] buffer) const @safe
    {
        if (!tryInto(buffer))
            throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");
        return buffer;
    }
}

/++
    Creates a cryptographically secure Nano ID generator using a custom
    alphabet and default size.

    The alphabet must contain between 1 and 256 Unicode code points.
    Can be evaluated at compile time (CTFE).

    Params:
        alphabet = Allowed symbols for generated IDs (1..256 Unicode symbols).
        size     = Default length of generated IDs in symbols (default: 21).

    Returns:
        A callable `NanoIdGenerator`.

    Throws:
        `NanoIdException` if `alphabet` is empty, has more than 256 symbols,
        or contains invalid UTF-8.
 +/
NanoIdGenerator customAlphabet(string alphabet, size_t size = defaultSize) pure @safe
{
    return NanoIdGenerator(ParsedAlphabet.parse(alphabet), size);
}

// ---------------------------------------------------------------------------
// Custom Random Generator
// ---------------------------------------------------------------------------

private enum bool isByteFiller(R) = is(typeof((ref R r, ubyte[] buf) { r(buf); }));
private enum bool isByteSupplier(R) = is(typeof((ref R r) { const(ubyte)[] b = r(size_t(1)); }));

/++
    A Nano ID generator backed by a user-supplied random source.

    Supports three kinds of random sources:
    $(LIST
        * Any `std.random` uniform RNG (`isUniformRNG!Rng`, e.g. `Mt19937`, `Xorshift`)
        * A buffer-filling callable `void(ubyte[])`
        * A byte-slice-returning callable `const(ubyte)[](size_t)` (mirrors JS `customRandom`)
    )
 +/
struct CustomRandomGenerator(Rng)
{
    private ParsedAlphabet _alphabet;
    private size_t _defaultSize;
    private Rng _rng;

    /// Returns the default ID length (in symbols).
    size_t defaultSize() const pure nothrow @safe @nogc
    {
        return _defaultSize;
    }

    /// Returns the number of symbols in this generator's alphabet.
    size_t alphabetLength() const pure nothrow @safe @nogc
    {
        return _alphabet.length;
    }

    /// Generates an ID of length `defaultSize`.
    string opCall()
    {
        return opCall(_defaultSize);
    }

    /// Generates an ID containing `size` symbols using the custom random source.
    string opCall(size_t size)
    {
        if (size == 0)
            return "";

        if (_alphabet.length == 1)
        {
            if (_alphabet.isAscii)
            {
                auto buf = new char[size];
                buf[] = _alphabet.ascii[0];
                return () @trusted { return assumeUnique(buf); }();
            }

            char[4] encoded;
            immutable size_t unitLen = encode(encoded, _alphabet.unicode[0]);
            auto buf = new char[unitLen * size];
            for (size_t i = 0; i < buf.length; i += unitLen)
                buf[i .. i + unitLen] = encoded[0 .. unitLen];
            return () @trusted { return assumeUnique(buf); }();
        }

        static if (isUniformRNG!Rng)
        {
            return generateFromUniformRng(size);
        }
        else static if (isByteFiller!Rng)
        {
            return generateFromByteFiller(size);
        }
        else static if (isByteSupplier!Rng)
        {
            return generateFromByteSupplier(size);
        }
        else
        {
            static assert(false,
                "Unsupported random source type `" ~ Rng.stringof ~
                "`. Expected a std.random UniformRNG, `void(ubyte[])`, or `ubyte[](size_t)`."
            );
        }
    }

    static if (isUniformRNG!Rng)
    private string generateFromUniformRng(size_t size)
    {
        if (_alphabet.isAscii)
        {
            auto buf = new char[size];
            foreach (ref char c; buf)
                c = _alphabet.ascii[uniform!"[)"(size_t(0), _alphabet.length, _rng)];
            return () @trusted { return assumeUnique(buf); }();
        }

        auto app = appender!string();
        app.reserve(size * 2);
        foreach (_; 0 .. size)
            app.put(_alphabet.unicode[uniform!"[)"(size_t(0), _alphabet.length, _rng)]);
        return app.data;
    }

    static if (!isUniformRNG!Rng && isByteFiller!Rng)
    private string generateFromByteFiller(size_t size)
    {
        if (_alphabet.isAscii)
        {
            auto buf = new char[size];
            if (_alphabet.isPowerOfTwo)
            {
                _rng(() @trusted { return cast(ubyte[]) buf; }());
                immutable uint mask = _alphabet.mask;
                foreach (ref char c; buf)
                    c = _alphabet.ascii[cast(ubyte) c & mask];
                return () @trusted { return assumeUnique(buf); }();
            }

            ubyte[256] stackBuf;
            immutable uint cutoff = _alphabet.safeByteCutoff;
            size_t written = 0;
            while (written < size)
            {
                immutable size_t remaining = size - written;
                size_t step = computeStep(remaining, cutoff, 256);
                ubyte[] rnd = step <= stackBuf.length ? stackBuf[0 .. step] : new ubyte[step];
                _rng(rnd);

                foreach (ubyte b; rnd)
                {
                    if (b < cutoff)
                    {
                        buf[written++] = _alphabet.ascii[b % _alphabet.length];
                        if (written == size)
                            break;
                    }
                }
            }
            return () @trusted { return assumeUnique(buf); }();
        }

        auto app = appender!string();
        app.reserve(size * 2);
        ubyte[256] stackBuf;
        size_t written = 0;

        if (_alphabet.isPowerOfTwo)
        {
            immutable uint mask = _alphabet.mask;
            while (written < size)
            {
                immutable size_t remaining = size - written;
                ubyte[] rnd = remaining <= stackBuf.length ? stackBuf[0 .. remaining] : new ubyte[remaining];
                _rng(rnd);
                foreach (ubyte b; rnd)
                {
                    app.put(_alphabet.unicode[b & mask]);
                    if (++written == size)
                        break;
                }
            }
            return app.data;
        }

        immutable uint cutoff = _alphabet.safeByteCutoff;
        while (written < size)
        {
            immutable size_t remaining = size - written;
            size_t step = computeStep(remaining, cutoff, 256);
            ubyte[] rnd = step <= stackBuf.length ? stackBuf[0 .. step] : new ubyte[step];
            _rng(rnd);
            foreach (ubyte b; rnd)
            {
                if (b < cutoff)
                {
                    app.put(_alphabet.unicode[b % _alphabet.length]);
                    if (++written == size)
                        break;
                }
            }
        }
        return app.data;
    }

    static if (!isUniformRNG!Rng && !isByteFiller!Rng && isByteSupplier!Rng)
    private string generateFromByteSupplier(size_t size)
    {
        if (_alphabet.isAscii)
        {
            auto buf = new char[size];
            size_t written = 0;

            if (_alphabet.isPowerOfTwo)
            {
                immutable uint mask = _alphabet.mask;
                while (written < size)
                {
                    const(ubyte)[] bytes = _rng(size - written);
                    if (bytes.length == 0)
                        throw new NanoIdException("Custom random generator returned an empty byte slice.");

                    foreach (ubyte b; bytes)
                    {
                        buf[written++] = _alphabet.ascii[b & mask];
                        if (written == size)
                            break;
                    }
                }
                return () @trusted { return assumeUnique(buf); }();
            }

            immutable uint cutoff = _alphabet.safeByteCutoff;
            immutable size_t step = computeStep(size, cutoff, 256);
            while (written < size)
            {
                const(ubyte)[] bytes = _rng(step);
                if (bytes.length == 0)
                    throw new NanoIdException("Custom random generator returned an empty byte slice.");

                foreach (ubyte b; bytes)
                {
                    if (b < cutoff)
                    {
                        buf[written++] = _alphabet.ascii[b % _alphabet.length];
                        if (written == size)
                            break;
                    }
                }
            }
            return () @trusted { return assumeUnique(buf); }();
        }

        auto app = appender!string();
        app.reserve(size * 2);
        size_t written = 0;

        if (_alphabet.isPowerOfTwo)
        {
            immutable uint mask = _alphabet.mask;
            while (written < size)
            {
                const(ubyte)[] bytes = _rng(size - written);
                if (bytes.length == 0)
                    throw new NanoIdException("Custom random generator returned an empty byte slice.");

                foreach (ubyte b; bytes)
                {
                    app.put(_alphabet.unicode[b & mask]);
                    if (++written == size)
                        break;
                }
            }
            return app.data;
        }

        immutable uint cutoff = _alphabet.safeByteCutoff;
        immutable size_t step = computeStep(size, cutoff, 256);
        while (written < size)
        {
            const(ubyte)[] bytes = _rng(step);
            if (bytes.length == 0)
                throw new NanoIdException("Custom random generator returned an empty byte slice.");

            foreach (ubyte b; bytes)
            {
                if (b < cutoff)
                {
                    app.put(_alphabet.unicode[b % _alphabet.length]);
                    if (++written == size)
                        break;
                }
            }
        }
        return app.data;
    }
}

/++
    Creates a Nano ID generator using a custom alphabet, default size, and
    custom random source.

    Params:
        alphabet = Allowed symbols for generated IDs (1..256 Unicode symbols).
        size     = Default length of generated IDs in symbols.
        rng      = A `std.random` uniform RNG, `void(ubyte[])` buffer filler,
                   or `const(ubyte)[](size_t)` byte supplier.

    Returns:
        A callable `CustomRandomGenerator!Rng`.

    Throws:
        `NanoIdException` if `alphabet` is empty, has more than 256 symbols,
        or contains invalid UTF-8.
 +/
CustomRandomGenerator!Rng customRandom(Rng)(string alphabet, size_t size, Rng rng)
{
    static assert(
        isUniformRNG!Rng || isByteFiller!Rng || isByteSupplier!Rng,
        "Unsupported random source type `" ~ Rng.stringof ~
        "`. Expected a std.random UniformRNG, `void(ubyte[])`, or `ubyte[](size_t)`."
    );
    return CustomRandomGenerator!Rng(ParsedAlphabet.parse(alphabet), size, rng);
}

/// Overload of `customRandom` using `defaultSize` (21).
CustomRandomGenerator!Rng customRandom(Rng)(string alphabet, Rng rng)
{
    return customRandom(alphabet, defaultSize, rng);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

unittest
{
    // urlAlphabet invariants: 64 unique URL-safe symbols.
    assert(urlAlphabet.length == 64);
    bool[256] seen;
    foreach (char c; urlAlphabet)
    {
        assert(!seen[cast(ubyte) c], "Duplicate character in urlAlphabet");
        seen[cast(ubyte) c] = true;
        immutable bool valid =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-';
        assert(valid);
    }
}

unittest
{
    import std.algorithm.searching : canFind;

    // Basic nanoid() generation, lengths, and aliases.
    assert(nanoid(0) == "");
    assert(generate(0) == "");

    foreach (_; 0 .. 100)
    {
        string id = nanoid();
        assert(id.length == 21);
        foreach (char c; id)
            assert(urlAlphabet.canFind(c));
    }

    assert(nanoid(10).length == 10);
    assert(generate(15).length == 15);

    // Large IDs exceeding both pool size (4096) and 65536 bytes.
    string large1 = nanoid(1000);
    assert(large1.length == 1000);
    foreach (char c; large1)
        assert(urlAlphabet.canFind(c));

    string large2 = nanoid(70_000);
    assert(large2.length == 70_000);
    foreach (char c; large2)
        assert(urlAlphabet.canFind(c));
}

unittest
{
    import std.algorithm.searching : canFind;

    // Stack-allocated fixed-size and @nogc in-place buffer APIs.
    char[0] empty = nanoid!0();
    assert(empty.length == 0);

    char[21] fixed = nanoid!21();
    foreach (char c; fixed)
        assert(urlAlphabet.canFind(c));

    char[10] fixedShort = generate!10();
    foreach (char c; fixedShort)
        assert(urlAlphabet.canFind(c));

    char[21] buf;
    auto returned = nanoidInto(buf[]);
    assert(returned.ptr == buf.ptr && returned.length == 21);
    foreach (char c; buf)
        assert(urlAlphabet.canFind(c));

    static void checkNoGc() @safe nothrow @nogc
    {
        char[21] localBuf;
        assert(tryNanoidInto(localBuf[]));
    }
    checkNoGc();
}

unittest
{
    // Collision check across 50,000 IDs.
    bool[string] seen;
    foreach (_; 0 .. 50_000)
    {
        string id = nanoid();
        assert(id !in seen);
        seen[id] = true;
    }
}

unittest
{
    // Uniform distribution test for default nanoid() (mirrors JS Nano ID test).
    enum size_t count = 100_000;
    enum size_t len = defaultSize;

    size_t[256] counts;
    foreach (_; 0 .. count)
    {
        char[len] id = nanoid!len();
        foreach (char c; id)
            ++counts[cast(ubyte) c];
    }

    double minDist = double.max;
    double maxDist = 0.0;
    size_t distinct = 0;
    foreach (char c; urlAlphabet)
    {
        immutable size_t n = counts[cast(ubyte) c];
        if (n > 0)
            ++distinct;
        immutable double dist = (cast(double) n * urlAlphabet.length) / (count * len);
        if (dist < minDist) minDist = dist;
        if (dist > maxDist) maxDist = dist;
    }
    assert(distinct == urlAlphabet.length);
    assert(maxDist - minDist <= 0.05);
}

unittest
{
    import core.thread : Thread;

    // Multi-threaded safety: TLS pools must never race or duplicate IDs.
    enum size_t threadCount = 8;
    enum size_t perThread = 5_000;
    auto results = new string[][threadCount];

    Thread[threadCount] threads;
    foreach (t; 0 .. threadCount)
    {
        threads[t] = ((size_t tid) {
            return new Thread(() {
                auto local = new string[perThread];
                foreach (i; 0 .. perThread)
                    local[i] = nanoid();
                results[tid] = local;
            });
        })(t);
        threads[t].start();
    }

    foreach (t; threads)
        t.join();

    bool[string] allIds;
    foreach (batch; results)
    {
        foreach (id; batch)
        {
            assert(id.length == 21);
            assert(id !in allIds);
            allIds[id] = true;
        }
    }
    assert(allIds.length == threadCount * perThread);
}

unittest
{
    import std.algorithm.searching : canFind;
    import std.exception : assertThrown;
    import std.range.primitives : walkLength;
    import std.utf : byDchar;

    // CTFE & static immutable customAlphabet generators.
    static immutable hexGen = customAlphabet("0123456789abcdef", 10);
    static immutable uniGen = customAlphabet("абвгд", 8);

    assert(hexGen.defaultSize == 10);
    assert(hexGen.alphabetLength == 16);
    assert(hexGen.isAscii);

    assert(uniGen.defaultSize == 8);
    assert(uniGen.alphabetLength == 5);
    assert(!uniGen.isAscii);

    string h = hexGen();
    assert(h.length == 10);
    foreach (char c; h)
        assert("0123456789abcdef".canFind(c));
    assert(hexGen(5).length == 5);
    assert(hexGen(0) == "");

    // Single-symbol ASCII & Unicode alphabets.
    assert(customAlphabet("a", 5)() == "aaaaa");
    assert(customAlphabet("a")(10) == "aaaaaaaaaa");
    assert(customAlphabet("🚀", 4)() == "🚀🚀🚀🚀");

    // Zero default size must not hang when called with non-zero size.
    auto zeroDefault = customAlphabet("абв", 0);
    assert(zeroDefault() == "");
    string z8 = zeroDefault(8);
    assert(z8.byDchar.walkLength == 8);
    foreach (dchar c; z8.byDchar)
        assert("абв".byDchar.canFind(c));

    // Multi-byte Unicode alphabets (Cyrillic, CJK, emoji power-of-two & non-power-of-two).
    foreach (alphabet; ["абвгд", "あいうえお", "😀🚀🔥✨", "😀🚀🔥"])
    {
        auto gen = customAlphabet(alphabet, 12);
        foreach (_; 0 .. 50)
        {
            string id = gen();
            assert(id.byDchar.walkLength == 12);
            foreach (dchar c; id.byDchar)
                assert(alphabet.byDchar.canFind(c));
        }
    }

    // Exact boundary: 256-symbol alphabet succeeds.
    dchar[256] syms256;
    foreach (i; 0 .. 256)
        syms256[i] = cast(dchar)(0x0100 + i);
    import std.conv : to;
    string alpha256 = syms256[].to!string;
    auto gen256 = customAlphabet(alpha256, 32);
    assert(gen256.alphabetLength == 256);
    assert(gen256().byDchar.walkLength == 32);

    // Invalid alphabets throw NanoIdException.
    assertThrown!NanoIdException(customAlphabet(""));
    auto ascii257 = new char[257];
    ascii257[] = 'a';
    assertThrown!NanoIdException(customAlphabet(ascii257.idup));
    assertThrown!NanoIdException(customAlphabet(alpha256 ~ "Ω"));

    // Invalid UTF-8 throws NanoIdException.
    immutable char[2] badUtf8 = [cast(char) 0xFF, cast(char) 0xFE];
    assertThrown!NanoIdException(customAlphabet(badUtf8.idup));

    // @nogc buffer filling for ASCII & dchar[] for Unicode.
    static void checkCustomNoGc() @safe nothrow @nogc
    {
        char[16] cbuf;
        assert(hexGen.tryInto(cbuf[]));
        assert(!uniGen.tryInto(cbuf[]));

        dchar[16] dbuf;
        assert(hexGen.tryInto(dbuf[]));
        assert(uniGen.tryInto(dbuf[]));
    }
    checkCustomNoGc();

    char[8] cbuf;
    assertThrown!NanoIdException(uniGen.into(cbuf[]));
    dchar[8] dbuf;
    uniGen.into(dbuf[]);
    foreach (dchar c; dbuf)
        assert("абвгд".byDchar.canFind(c));
}

unittest
{
    // Flat distribution test for non-power-of-two customAlphabet (26 letters).
    enum size_t count = 50_000;
    enum size_t len = 30;
    enum string alphabet = "abcdefghijklmnopqrstuvwxyz";
    auto gen = customAlphabet(alphabet, len);

    size_t[256] counts;
    char[len] buf;
    foreach (_; 0 .. count)
    {
        gen.into(buf[]);
        foreach (char c; buf)
            ++counts[cast(ubyte) c];
    }

    double minDist = double.max;
    double maxDist = 0.0;
    size_t distinct = 0;
    foreach (char c; alphabet)
    {
        immutable size_t n = counts[cast(ubyte) c];
        if (n > 0)
            ++distinct;
        immutable double dist = (cast(double) n * alphabet.length) / (count * len);
        if (dist < minDist) minDist = dist;
        if (dist > maxDist) maxDist = dist;
    }
    assert(distinct == alphabet.length);
    assert(maxDist - minDist <= 0.05);
}

unittest
{
    import std.exception : assertThrown;
    import nanoid.random : _resetTestPool, _testRandomOverride;

    // Error recovery during nanoid() and customAlphabet().
    _resetTestPool();
    _testRandomOverride = (scope ubyte[]) nothrow @nogc => false;
    scope (exit)
    {
        _testRandomOverride = null;
        _resetTestPool();
    }

    auto asciiNonPow2 = customAlphabet("abcdef", 10);
    auto asciiPow2 = customAlphabet("abcd", 10);
    auto uniNonPow2 = customAlphabet("абвгд", 10);
    auto uniPow2 = customAlphabet("абвг", 10);

    assertThrown!NanoIdException(nanoid());
    assertThrown!NanoIdException(nanoid!21());
    assertThrown!NanoIdException(asciiNonPow2());
    assertThrown!NanoIdException(asciiPow2());
    assertThrown!NanoIdException(uniNonPow2());
    assertThrown!NanoIdException(uniPow2());

    // Restore and confirm full recovery.
    _testRandomOverride = null;
    assert(nanoid().length == 21);
    assert(asciiNonPow2().length == 10);
    assert(asciiPow2().length == 10);
}

unittest
{
    import std.algorithm.searching : canFind;
    import std.exception : assertThrown;
    import std.random : MinstdRand, Mt19937;
    import std.range.primitives : walkLength;
    import std.utf : byDchar;

    // 1. customRandom with std.random UniformRNG (deterministic & reproducible).
    auto genA = customRandom("abcdef", 10, Mt19937(42));
    auto genB = customRandom("abcdef", 10, Mt19937(42));
    string a1 = genA();
    string b1 = genB();
    assert(a1.length == 10);
    assert(a1 == b1);
    assert(genA() == genB());
    assert(genA() != a1);

    // Unicode + std.random UniformRNG.
    auto uniRng = customRandom("абвгд", 8, Mt19937(123));
    string u1 = uniRng();
    assert(u1.byDchar.walkLength == 8);
    foreach (dchar c; u1.byDchar)
        assert("абвгд".byDchar.canFind(c));

    // Non-power-of-two native range URNG (MinstdRand).
    auto lcgGen = customRandom("0123456789", 20, MinstdRand(7));
    string lcgId = lcgGen();
    assert(lcgId.length == 20);
    foreach (char c; lcgId)
        assert("0123456789".canFind(c));

    // 2. customRandom with byte-filling callback void(ubyte[]).
    // Verify safeByteCutoff rejects 255 for 5-symbol alphabet ("abcde", cutoff = 255).
    immutable ubyte[] seq = [2, 255, 3, 7, 0, 1];
    auto fillerGen = customRandom("abcde", 5, (ubyte[] dst) {
        foreach (i, ref ubyte b; dst)
            b = seq[i % seq.length];
    });
    // Accepted bytes from seq: 2->'c', (skip 255), 3->'d', 7%5=2->'c', 0->'a', 1->'b'
    assert(fillerGen() == "cdcab");

    // Power-of-two alphabet with byte-filling callback.
    auto pow2Filler = customRandom("abcd", 4, (ubyte[] dst) {
        immutable ubyte[4] s = [0, 1, 2, 255];
        foreach (i, ref ubyte b; dst)
            b = s[i % s.length];
    });
    // 0&3='a', 1&3='b', 2&3='c', 255&3='d'
    assert(pow2Filler() == "abcd");

    // 3. customRandom with byte-returning callback ubyte[](size_t) (JS style).
    auto supplierGen = customRandom("abcde", 5, (size_t n) {
        auto outBuf = new ubyte[n];
        foreach (i, ref ubyte b; outBuf)
            b = seq[i % seq.length];
        return outBuf;
    });
    assert(supplierGen() == "cdcab");
    assert(supplierGen(0) == "");

    // Default size overload (21) with OS random().
    auto osCustom = customRandom(urlAlphabet, &random);
    assert(osCustom().length == 21);

    // Default size 0 with explicit size must not hang.
    auto zeroRng = customRandom("abc", 0, (size_t n) {
        auto b = new ubyte[n];
        b[] = 1;
        return b;
    });
    assert(zeroRng() == "");
    assert(zeroRng(8) == "bbbbbbbb");

    // Empty-slice callback throws NanoIdException instead of hanging.
    auto brokenSupplier = customRandom("abc", 5, (size_t _) => cast(ubyte[]) null);
    assertThrown!NanoIdException(brokenSupplier());
    auto brokenPow2 = customRandom("abcd", 5, (size_t _) => cast(ubyte[]) null);
    assertThrown!NanoIdException(brokenPow2());

    // Invalid alphabet rejected.
    assertThrown!NanoIdException(customRandom("", 5, Mt19937(1)));
}
