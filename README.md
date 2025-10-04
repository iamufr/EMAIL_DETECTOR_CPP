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

### Optimized Build (Recommended for Production)

For maximum performance with aggressive optimizations:

#### GCC
```bash
g++ -O3 -march=native -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

#### Clang
```bash
clang++ -O3 -march=native -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

#### With Link-Time Optimization (even faster)
```bash
g++ -O3 -march=native -flto -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

**Compiler Flags Explained:**
- `-O3` – Maximum optimization level (~20x speedup)
- `-march=native` – CPU-specific optimizations (SIMD, AVX)
- `-std=c++17` – C++17 standard support
- `-pthread` – POSIX threading support
- `-flto` – Link-time optimization (optional, slower compile)

**Performance:** ~62M operations/second on modern hardware

---

### Unoptimized Build (Debug Mode)

For development and debugging:

```bash
g++ -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

**Performance:** ~3-4M operations/second (20x slower than optimized)

**Use this for:**
- Development and testing
- Debugging with GDB/LLDB
- Better error messages and stack traces

---

## ▶️ Running the Program

### Linux/macOS
```bash
./EmailDetector
```

### Windows (PowerShell)
```powershell
./EmailDetector.exe
```

### Windows (CMD)
```cmd
EmailDetector.exe
```

---

## 📊 Expected Output

```
=== Correctness Tests ===
✓ PASS: "user@example.com"
✓ PASS: "test@domain"
...
Correctness: 9/9 tests passed

=== Production Email Detector Tests ===
SENSITIVE: "review-team@geeksforgeeks.org"
  => Found emails: review-team@geeksforgeeks.org
...

=== Production Email Detector Benchmark ===
Test cases: 23
Using 16 threads
Iterations per thread: 100000
Time taken: 556 ms
Operations per second: 72805755
Thread safety: PASSED
Memory safety: PASSED
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
g++ -O3 -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

### Windows MinGW Users
If `-pthread` causes errors on Windows, you can omit it:

```bash
g++ -O3 -march=native -std=c++17 EmailDetector.cpp -o EmailDetector
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
