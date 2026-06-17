# Building wolfMQTT on Windows

## Visual Studio solution (quickest start)

A pre-built Visual Studio solution is available at `wolfmqtt.sln` (VS2019+). Open it in Visual Studio, select a configuration (Debug or Release), and build.

Command-line build from a Developer Command Prompt:

```cmd
msbuild /m /p:Platform=x64 /p:Configuration=Release wolfmqtt.sln
```

## CMake (recommended for configurability)

CMake generates Visual Studio projects with full feature configurability and works with VS Code, Visual Studio, and command-line workflows.

```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64 -DWITH_WOLFSSL=C:\path\to\wolfssl\install
cmake --build . --config Release
```

For other architectures:

```cmd
:: Win32
cmake .. -G "Visual Studio 17 2022" -A Win32

:: ARM64
cmake .. -G "Visual Studio 17 2022" -A ARM64
```

### Pointing at wolfSSL

wolfMQTT requires wolfSSL for TLS. Build and install wolfSSL first, then pass its install prefix:

```cmd
cmake .. -G "Visual Studio 17 2022" -A x64 ^
  -DWITH_WOLFSSL=C:\wolfssl-install
```

Or point at a wolfSSL source tree:

```cmd
cmake .. -G "Visual Studio 17 2022" -A x64 ^
  -DWITH_WOLFSSL_TREE=C:\path\to\wolfssl
```

### Disabling TLS

For testing without wolfSSL:

```cmd
cmake .. -G "Visual Studio 17 2022" -A x64 -DWOLFMQTT_NO_TLS=yes
```

### VS Code integration

Install the CMake Tools extension, open the wolfMQTT directory, and VS Code will pick up CMakeLists.txt automatically. Configure, build, and debug from the CMake Tools sidebar.

## vcpkg

```cmd
vcpkg install wolfmqtt
```

This pulls in wolfSSL as a dependency automatically.

## MSYS2 (autoconf on Windows)

For a Linux-like build experience on Windows using MSYS2:

```bash
# Install dependencies in the MSYS2 shell
pacman -S gcc autotools base-devel autoconf

# Build as on Linux
./autogen.sh
./configure
make
make check
```

This gives access to the full `./configure` flag set and is the closest to how CI tests the codebase.
