# EMAIL DETECTOR

A **production-grade email detection library** written in modern C++ with performance, security, and correctness as top priorities.

## ✨ Features

* **RFC-compliant validation** – strict email format checks
* **Thread-safe** – safe for concurrent usage with multiple threads
* **Performance optimized** – lightweight, minimal memory footprint
* **Security hardened** – input size limits to prevent DoS attacks
* **Exception safe** – robust against runtime errors
* **Duplicate-free extraction** – collects unique valid emails only
* **Benchmark & Test Suite** – correctness validation and performance benchmarking included

## 📌 Use Cases

* Detect and extract email addresses from untrusted input
* Protect applications from leaking sensitive user data
* Preprocess logs, text, or messages for compliance checks

## 🚀 Included Components

* `SensitiveEmailDetector` – core detection and extraction logic
* `PerformanceTest` – correctness and performance testing framework
* Example usage in `main()`

## 🔧 Build Instructions

You can build the project using **Make** (recommended), **CMake**, or **Manual Compilation**.

### Option 1: Using Makefile (Recommended)

The included `Makefile` handles OS detection (Windows/Linux/macOS) and optimization flags automatically.

#### 1\. Debug Build (Default)

Best for development and debugging (includes symbols `-g`, disables optimizations `-O0`).

```bash
make
# OR
make build
```

#### 2\. Release Build (High Performance)

Best for production. Uses `-O3`, `-march=native`, and Link Time Optimization (`-flto`).

```bash
make build_release
```

#### 3\. CMake via Makefile

If you prefer using the CMake build system but want to trigger it via Make:

```bash
# Debug CMake build
make build_cmake

# Release CMake build
make build_release_cmake
```

#### 4\. Cleaning Up

Removes binaries and build artifacts.

```bash
make clean
```

-----

### Option 2: Manual Compilation

If you do not have `make` installed, you can compile manually.

#### GCC / Clang (For development)
```bash
# For GCC Compiler
g++ -O3 -march=native -std=c++23 -pthread EmailDetector.cpp -o EmailDetector

# For CLANG Compiler
clang++ -O3 -march=native -std=c++23 -pthread EmailDetector.cpp -o EmailDetector
```

#### GCC / Clang (For production/benchmarking)
```bash
# For GCC Compiler
g++ -O3 -march=native -flto=auto -DNDEBUG -std=c++23 -pthread EmailDetector.cpp -o EmailDetector

# For CLANG Compiler
clang++ -O3 -march=native -flto=auto -DNDEBUG -std=c++23 -pthread EmailDetector.cpp -o EmailDetector
```

**Compiler Flags Explained:**
- `-O3` – Maximum optimization level (~20x speedup)
- `-march=native` – CPU-specific optimizations (SIMD, AVX)
- `-std=c++23` – C++23 standard support
- `-pthread` – POSIX threading support
- `-flto` – Link-time optimization (optional, slower compile)

**Performance:** ~62M operations/second on modern hardware

---

### Unoptimized Build (Debug Mode)

For development and debugging:

```bash
g++ -g -std=c++23 -pthread EmailDetector.cpp -o EmailDetector
```

  * `-g` – Includes debugging information in the binary for use with tools like GDB.

-----

**Performance:** ~3-4M operations/second (20x slower than optimized)

**Use this for:**
- Development and testing
- Debugging with GDB/LLDB
- Better error messages and stack traces

---

## ▶️ Running the Program

### Using Makefile

The Makefile automatically handles the executable extension (`.exe`) and path separators for your OS.

```bash
# Run the standard/debug build
make run

# Run the release build (specifically targeted to the build/release folder)
make run_release_cmake
```

### Manual Execution

#### Linux/macOS
```bash
./EmailDetector
```

#### Windows (PowerShell)
```powershell
./EmailDetector.exe
```

#### Windows (CMD)
```cmd
EmailDetector.exe
```

---

## 📊 Expected Output

```
====================================================================================================
=== RFC 5322 EXACT VALIDATION ===
====================================================================================================
Full RFC 5322 compliance with quoted strings, IP literals, etc.

Γ£ô Standard format: "user@example.com"
Γ£ô Minimal valid: "a@b.co"
Γ£ô Dot in local part: "test.user@example.com"
Γ£ô Plus sign (Gmail filters): "user+tag@gmail.com"
Γ£ô Exclamation mark: "user!test@example.com"
Γ£ô Hash symbol: "user#tag@example.com"
Γ£ô Dollar sign: "user$admin@example.com"

.......
...........
..................... Continue

Γ£ô Space in domain: "user@domain .com"
Γ£ô Unclosed quote: ""unclosed@example.com"
Γ£ô Quote in middle without @: ""user"name@example.com"
Γ£ô Invalid IPv4 (3 octets): "user@[192.168.1]"
Γ£ô Invalid IPv4 (octet > 255): "user@[999.168.1.1]"
Γ£ô Invalid IPv4 (octet = 256): "user@[192.168.1.256]"
Γ£ô Invalid IPv6 (bad hex): "user@[gggg::1]"

Result: 109/109 passed (100%)

====================================================================================================


====================================================================================================
=== TEXT SCANNING (Content Detection) ===
====================================================================================================
Conservative validation for PII detection

Γ£ô long valid email
  Input: "aaaaaaaaaaaaaaaaaaaa@example.com"
  Found: aaaaaaaaaaaaaaaaaaaa@example.com

Γ£ô Multiple @ characters
  Input: "noise@@valid@domain.com"
  Found: valid@domain.com

Γ£ô Multiple invalid chars before @
  Input: "text###@@@user@domain.com"
  Found: user@domain.com

Γ£ô Legal email before second @
  Input: "text@user.com@domain."
  Found: text@user.com

Γ£ô Two legal emails
  Input: "text@user.com@domain.in"
  Found: text@user.com user.com@domain.in

Γ£ô Mixed invalid prefix
  Input: "text!!!%(%)%$$$user@domain.com"
  Found: user@domain.com

Γ£ô Multiple dots before valid part
  Input: "user....email@domain.com"
  Found: email@domain.com

.......
...........
..................... Continue

Γ£ô Apostrophe separate extraction
  Input: "That's john'semail@example.com works"
  Found: john'semail@example.com

Γ£ô IP literal in scan mode
  Input: "Server: user@[192.168.1.1]"

Γ£ô No TLD
  Input: "test@domain"

Γ£ô No @ symbol
  Input: "no emails here"

Γ£ô Period after email
  Input: "Contact: user@example.com."
  Found: user@example.com

Γ£ô Exclamation after email
  Input: "Email user@example.com!"
  Found: user@example.com

Γ£ô Question mark after email
  Input: "Really? user@example.com?"
  Found: user@example.com

Result: 244/244 passed (100%)

====================================================================================================


====================================================================================================
=== EMAIL DETECTION TEST ===
====================================================================================================
Testing both exact validation and text scanning

SENSITIVE: "Simple email: user@example.com in text"
  => Found emails: user@example.com

SENSITIVE: "Multiple emails: first@domain.com and second@another.org"
  => Found emails: first@domain.com second@another.org

SENSITIVE: "user..double@domain.com"
  => Found emails: double@domain.com

SENSITIVE: "Complex: john.doe+filter@sub.domain.co.uk mixed with text"
  => Found emails: john.doe+filter@sub.domain.co.uk

CLEAN    : "No emails in this text at all"

SENSITIVE: "Edge case: a@b.co minimal email"
  => Found emails: a@b.co

SENSITIVE: "review-team@geeksforgeeks.org"
  => Found emails: review-team@geeksforgeeks.org

.......
...........
..................... Continue

CLEAN    : "user@[999.168.1.1]"

CLEAN    : "user@[192.168.1.256]"

CLEAN    : "user@[gggg::1]"

====================================================================================================
Γ£ô Email Detection Complete
====================================================================================================

====================================================================================================
=== COMPREHENSIVE PERFORMANCE BENCHMARK ===
====================================================================================================
Configuration:
  Threads: 16
  Iterations per thread: 100000
  Test cases: 80
  Total operations per method: 128000000

----------------------------------------------------------------------------------------------------
BENCHMARK 1: isValid() - Exact Email Validation
----------------------------------------------------------------------------------------------------
Time: 614 ms
Operations: 128000000
Throughput: 208469055 ops/sec
Valid emails found: 59200000
Avg latency: 4.79688 ns/op

----------------------------------------------------------------------------------------------------
BENCHMARK 2: contains() - Fast Email Detection
----------------------------------------------------------------------------------------------------
Time: 1170 ms
Operations: 128000000
Throughput: 109401709 ops/sec
Texts with emails: 86400000
Avg latency: 9.14062 ns/op

----------------------------------------------------------------------------------------------------
BENCHMARK 3: extract() - Full Email Extraction
----------------------------------------------------------------------------------------------------
Time: 4678 ms
Operations: 128000000
Throughput: 27362120 ops/sec
Emails extracted: 94400000
Avg latency: 36.5469 ns/op

----------------------------------------------------------------------------------------------------
BENCHMARK 4: Combined Workload (Real-world)
----------------------------------------------------------------------------------------------------
Time: 7345 ms
Operations: 128000000
Throughput: 17426820 ops/sec
Results produced: 153600000
Avg latency: 57.3828 ns/op

====================================================================================================
Γ£ô Performance Benchmark Complete
====================================================================================================


====================================================================================================
Γ£ô 100% RFC 5322 COMPLIANT
Γ£ô SOLID Principles Applied
Γ£ô Thread-Safe Implementation
Γ£ô Production-Ready Performance
====================================================================================================

Features:
  ΓÇó Quoted strings: "user name"@example.com
  ΓÇó IP literals: user@[192.168.1.1] (exact mode only)
  ΓÇó All RFC 5322 special characters
  ΓÇó Alphanumeric TLDs
  ΓÇó Single-character TLDs
  ΓÇó Conservative text scanning (strict boundaries)
  ΓÇó Proper word boundary detection (no false positives)
====================================================================================================
```

---

## 🧪 Testing

The program includes built-in tests:
- **Correctness tests** – validates RFC compliance
- **Performance benchmark** – multi-threaded stress testing
- **Edge case validation** – DoS protection, size limits

---

## 📋 Requirements

- **Compiler:** GCC 7+ or Clang 6+ (C++17 support)
- **OS:** Linux, macOS, or Windows
- **Hardware:** Any modern CPU (optimized builds use CPU-specific instructions)

---

## ⚠️ Important Notes

### About `-march=native`
The optimized build uses `-march=native`, which generates code for **your specific CPU**. The binary may not run on older/different processors. For portable binaries, use:

```bash
g++ -O3 -std=c++23 -pthread EmailDetector.cpp -o EmailDetector
```

### Windows MinGW Users
If `-pthread` causes errors on Windows, you can omit it:

```bash
g++ -O3 -march=native -std=c++23 EmailDetector.cpp -o EmailDetector
```

---

## 📈 Performance Comparison

| Build Type | Time (ms) | Ops/Second | Speedup |
|------------|-----------|------------|---------|
| Unoptimized | ~11,395 | ~3.5M | 1x |
| Optimized `-O3` | ~556 | ~72.8M | **20x** |

**Conclusion:** Always use optimized builds for production deployments.

---

## 🛡️ Security Features

- **Input size validation** – 1MB limit prevents DoS attacks
- **No buffer overflows** – bounds checking on all array access
- **Exception safety** – graceful handling of runtime errors
- **Thread-safe design** – no data races in concurrent execution

---

This project is designed as a **ready-to-use utility** for integrating sensitive email detection into high-performance C++ systems.
