Import("env")

import os

platform = env.PioPlatform()
toolchain = platform.get_package_dir("toolchain-gccmingw32")
if not toolchain:
    raise RuntimeError("pinned PlatformIO MinGW toolchain was not installed")
env.PrependENVPath("PATH", os.path.join(toolchain, "bin"))
env.Append(
    LINKFLAGS=[
        "-static",
        "-static-libgcc",
        "-static-libstdc++",
    ]
)
