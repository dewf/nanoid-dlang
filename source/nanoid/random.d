/++
    Cryptographically secure random byte generation using the operating
    system's native CSPRNG, plus a lock-free thread-local entropy pool.

    Supported backends:
    $(LIST
        * Windows: `BCryptGenRandom` (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`)
        * macOS / iOS / BSDs: `arc4random_buf`
        * Linux: `getrandom(2)` with `/dev/urandom` fallback on `ENOSYS`
        * Other POSIX: `/dev/urandom`
    )
 +/
module nanoid.random;

import std.exception : basicExceptionCtors;

/// Exception thrown on invalid Nano ID configuration or CSPRNG failure.
class NanoIdException : Exception
{
    mixin basicExceptionCtors;
}

version (Windows)
{
    pragma(lib, "bcrypt");

    private enum uint BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

    private extern (Windows) int BCryptGenRandom(
        void* hAlgorithm,
        ubyte* pbBuffer,
        uint cbBuffer,
        uint dwFlags
    ) nothrow @nogc;
}
else version (OSX)
    version = HasArc4RandomBuf;
else version (iOS)
    version = HasArc4RandomBuf;
else version (TVOS)
    version = HasArc4RandomBuf;
else version (WatchOS)
    version = HasArc4RandomBuf;
else version (FreeBSD)
    version = HasArc4RandomBuf;
else version (OpenBSD)
    version = HasArc4RandomBuf;
else version (NetBSD)
    version = HasArc4RandomBuf;
else version (DragonFlyBSD)
    version = HasArc4RandomBuf;

version (HasArc4RandomBuf)
{
    private extern (C) void arc4random_buf(void* buf, size_t nbytes) nothrow @nogc;
}
else version (linux)
{
    import core.stdc.errno : errno, EINTR, ENOSYS;
    import core.sys.posix.sys.types : ssize_t;

    private extern (C) ssize_t getrandom(void* buf, size_t buflen, uint flags) nothrow @nogc;
}

version (Posix)
{
    import core.sys.posix.pthread : pthread_atfork;

    // Incremented in the child process after fork() so each thread invalidates
    // any inherited TLS pool bytes before using them.
    private __gshared size_t _forkGeneration = 0;
    private size_t _poolForkGeneration = 0;

    private extern (C) void _onForkChild() nothrow @nogc
    {
        ++_forkGeneration;
    }

    shared static this()
    {
        pthread_atfork(null, null, &_onForkChild);
    }
}

version (unittest)
{
    package(nanoid) bool delegate(scope ubyte[]) nothrow @nogc _testRandomOverride;
}

/++
    Fills `buffer` with cryptographically secure random bytes from the OS.

    This is the `@nogc nothrow` primitive underlying `fillRandom` and `random`.

    Params:
        buffer = Destination slice to fill. An empty slice succeeds immediately.

    Returns:
        `true` if all bytes were filled, or `false` if the OS CSPRNG failed.
 +/
bool tryFillRandom(scope ubyte[] buffer) @trusted nothrow @nogc
{
    if (buffer.length == 0)
        return true;

    version (unittest)
    {
        if (_testRandomOverride !is null)
            return _testRandomOverride(buffer);
    }

    version (Windows)
    {
        size_t offset = 0;
        while (offset < buffer.length)
        {
            immutable size_t remaining = buffer.length - offset;
            immutable uint chunk = remaining > uint.max ? uint.max : cast(uint) remaining;
            immutable int status = BCryptGenRandom(
                null,
                buffer.ptr + offset,
                chunk,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
            if (status < 0)
                return false;
            offset += chunk;
        }
        return true;
    }
    else version (HasArc4RandomBuf)
    {
        arc4random_buf(buffer.ptr, buffer.length);
        return true;
    }
    else version (linux)
    {
        size_t offset = 0;
        while (offset < buffer.length)
        {
            immutable ssize_t n = getrandom(
                buffer.ptr + offset,
                buffer.length - offset,
                0
            );
            if (n > 0)
            {
                offset += cast(size_t) n;
            }
            else if (n == -1)
            {
                immutable int err = errno;
                if (err == EINTR)
                    continue;
                if (err == ENOSYS)
                    return tryFillFromUrandom(buffer[offset .. $]);
                return false;
            }
            else
            {
                return false;
            }
        }
        return true;
    }
    else version (Posix)
    {
        return tryFillFromUrandom(buffer);
    }
    else
    {
        static assert(false, "Unsupported platform: no cryptographic random generator available.");
    }
}

version (Posix)
private bool tryFillFromUrandom(scope ubyte[] buffer) @trusted nothrow @nogc
{
    import core.stdc.errno : errno, EINTR;
    import core.sys.posix.fcntl : open, O_RDONLY;
    import core.sys.posix.unistd : close, read;

    static if (__traits(compiles, { import core.sys.posix.fcntl : O_CLOEXEC; return O_CLOEXEC; }))
    {
        import core.sys.posix.fcntl : O_CLOEXEC;
        enum int openFlags = O_RDONLY | O_CLOEXEC;
    }
    else
    {
        enum int openFlags = O_RDONLY;
    }

    int fd = -1;
    while (true)
    {
        fd = open("/dev/urandom", openFlags);
        if (fd >= 0)
            break;
        if (errno != EINTR)
            return false;
    }
    scope (exit) close(fd);

    size_t offset = 0;
    while (offset < buffer.length)
    {
        immutable auto n = read(fd, buffer.ptr + offset, buffer.length - offset);
        if (n > 0)
        {
            offset += cast(size_t) n;
        }
        else if (n == -1)
        {
            if (errno == EINTR)
                continue;
            return false;
        }
        else
        {
            return false;
        }
    }
    return true;
}

/++
    Fills `buffer` in place with cryptographically secure random bytes.

    Params:
        buffer = Destination slice to fill.

    Throws:
        `NanoIdException` if the operating system's CSPRNG fails.
 +/
void fillRandom(scope ubyte[] buffer) @safe
{
    if (!tryFillRandom(buffer))
        throw new NanoIdException("Failed to obtain cryptographically secure random bytes from the OS.");
}

/++
    Allocates and returns a buffer of `size` cryptographically secure random bytes.

    Params:
        size = Number of random bytes to generate.

    Returns:
        A newly allocated `ubyte[]` of length `size`.

    Throws:
        `NanoIdException` if the operating system's CSPRNG fails.
 +/
ubyte[] random(size_t size) @safe
{
    if (size == 0)
        return null;

    auto buffer = new ubyte[size];
    fillRandom(buffer);
    return buffer;
}

// ---------------------------------------------------------------------------
// Thread-local entropy pool (lock-free, lazily initialized, fork-safe)
// ---------------------------------------------------------------------------

private enum size_t poolSize = 4096;
private ubyte[poolSize] _pool;
private size_t _poolOffset = poolSize; // Empty until first refill.

/++
    Fills `dest` using the thread-local CSPRNG byte pool.

    Large requests bypass the pool and read directly from the OS CSPRNG.
    Consumed bytes are scrubbed immediately after being copied out.
 +/
package(nanoid) bool tryFillPooledRandom(scope ubyte[] dest) @trusted nothrow @nogc
{
    if (dest.length == 0)
        return true;

    if (dest.length > poolSize / 2)
        return tryFillRandom(dest);

    version (Posix)
    {
        if (_poolForkGeneration != _forkGeneration)
        {
            _pool[] = 0;
            _poolOffset = poolSize;
            _poolForkGeneration = _forkGeneration;
        }
    }

    if (_poolOffset + dest.length > poolSize)
    {
        // Mark the pool empty before refilling so a CSPRNG failure never
        // exposes stale or zeroed bytes on subsequent calls.
        _poolOffset = poolSize;
        if (!tryFillRandom(_pool[]))
            return false;
        _poolOffset = 0;
    }

    immutable size_t start = _poolOffset;
    immutable size_t end = start + dest.length;
    dest[] = _pool[start .. end];
    _pool[start .. end] = 0;
    _poolOffset = end;
    return true;
}

version (unittest)
package(nanoid) void _resetTestPool() nothrow @nogc
{
    _pool[] = 0;
    _poolOffset = poolSize;
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

unittest
{
    // Empty requests succeed cleanly without error.
    assert(random(0).length == 0);
    ubyte[] empty;
    fillRandom(empty);
    assert(tryFillRandom(empty));
    assert(tryFillPooledRandom(empty));
}

unittest
{
    // Verify tryFillRandom and tryFillPooledRandom are @safe nothrow @nogc.
    static void checkNoGc() @safe nothrow @nogc
    {
        ubyte[32] a;
        assert(tryFillRandom(a[]));
        ubyte[21] b;
        assert(tryFillPooledRandom(b[]));
    }
    checkNoGc();
}

unittest
{
    // Small, medium, and large random buffers (including > 65536 bytes).
    foreach (_; 0 .. 64)
        assert(random(10).length == 10);

    auto bytes = random(1000);
    assert(bytes.length == 1000);
    bool[256] seen;
    size_t uniqueCount = 0;
    foreach (ubyte b; bytes)
    {
        if (!seen[b])
        {
            seen[b] = true;
            ++uniqueCount;
        }
    }
    // 1000 uniform random bytes should cover well over 200 distinct byte values.
    assert(uniqueCount > 200);

    auto big = random(70_000);
    assert(big.length == 70_000);
}

unittest
{
    import std.exception : assertThrown;

    // Error recovery: CSPRNG failure must throw NanoIdException without
    // leaving the TLS pool in a corrupted state.
    ubyte[16] warmup;
    assert(tryFillPooledRandom(warmup[]));

    _resetTestPool();
    _testRandomOverride = (scope ubyte[]) nothrow @nogc => false;
    scope (exit)
    {
        _testRandomOverride = null;
        _resetTestPool();
    }

    ubyte[16] buf;
    assert(!tryFillRandom(buf[]));
    assert(!tryFillPooledRandom(buf[]));
    assertThrown!NanoIdException(fillRandom(buf[]));
    assertThrown!NanoIdException(random(64));

    // Restore OS CSPRNG and verify recovery.
    _testRandomOverride = null;
    auto recovered = random(32);
    assert(recovered.length == 32);
    assert(tryFillPooledRandom(buf[]));
}
