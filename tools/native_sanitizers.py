"""Enable native memory diagnostics supported by the selected host toolchain."""

import os

Import("env")  # noqa: F821 - injected by PlatformIO/SCons

if os.name == "nt":
    # PlatformIO's pinned MinGW 5.1 package does not ship libasan/libubsan.
    # Keep the required environment useful and deterministic on the supported
    # Windows development host with checked libstdc++ iterators and stack
    # canaries. The build output is explicit so this is never misreported as an
    # AddressSanitizer run.
    env.Append(  # noqa: F821 - injected by PlatformIO/SCons
        CXXFLAGS=[
            "-D_GLIBCXX_DEBUG",
            "-D_GLIBCXX_DEBUG_PEDANTIC",
            "-fstack-protector-all",
        ],
        LINKFLAGS=["-fstack-protector-all"],
    )
    print(
        "native-sanitized: MinGW ASan/UBSan runtime unavailable; "
        "using checked iterators and stack protector"
    )
else:
    sanitizer_flags = [
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
    ]
    env.Append(  # noqa: F821 - injected by PlatformIO/SCons
        CFLAGS=sanitizer_flags,
        CXXFLAGS=sanitizer_flags,
        LINKFLAGS=["-fsanitize=address,undefined,leak"],
    )
    print("native-sanitized: AddressSanitizer, UBSan, and LeakSanitizer enabled")
