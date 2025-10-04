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
**For development:**
```bash
g++ -O3 -march=native -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
```

#### GCC 
**For production/benchmarking:**
```bash
g++ -O3 -march=native -flto -DNDEBUG -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
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
=== RFC 5322 EXACT VALIDATION ===
Full RFC 5322 compliance with quoted strings, IP literals, etc.

Γ£ô Standard format: "user@example.com"
Γ£ô Minimal valid: "a@b.co"
Γ£ô Dot in local part: "test.user@example.com"
Γ£ô Plus sign (Gmail filters): "user+tag@gmail.com"
Γ£ô Exclamation mark: "user!test@example.com"
Γ£ô Hash symbol: "user#tag@example.com"
Γ£ô Dollar sign: "user$admin@example.com"
Γ£ô Percent sign: "user%percent@example.com"
Γ£ô Ampersand: "user&name@example.com"
Γ£ô Apostrophe: "user'quote@example.com"
Γ£ô Asterisk: "user*star@example.com"
Γ£ô Equal sign: "user=equal@example.com"
Γ£ô Question mark: "user?question@example.com"
Γ£ô Caret: "user^caret@example.com"
Γ£ô Underscore: "user_underscore@example.com"
Γ£ô Backtick: "user`backtick@example.com"
Γ£ô Opening brace: "user{brace@example.com"
Γ£ô Pipe: "user|pipe@example.com"
Γ£ô Closing brace: "user}brace@example.com"
Γ£ô Tilde: "user~tilde@example.com"
Γ£ô Simple quoted string: ""user"@example.com"
Γ£ô Quoted string with space: ""user name"@example.com"
Γ£ô Quoted string with @: ""user@internal"@example.com"
Γ£ô Quoted string with dot: ""user.name"@example.com"
Γ£ô Escaped quote in quoted string: ""user\"name"@example.com"
Γ£ô Escaped backslash: ""user\\name"@example.com"
Γ£ô IPv4 literal: "user@[192.168.1.1]"
Γ£ô IPv6 literal: "user@[IPv6:2001:db8::1]"
Γ£ô IPv6 literal: "user@[2001:db8::1]"
Γ£ô Private IPv4: "test@[10.0.0.1]"
Γ£ô IPv6 link-local: "user@[fe80::1]"
Γ£ô IPv6 loopback: "user@[::1]"
Γ£ô IPv6 loopback: "user@[::1]"
Γ£ô IPv6 all zeros: "user@[::]"
Γ£ô IPv6 trailing compression: "user@[2001:db8::]"
Γ£ô IPv4-mapped IPv6: "user@[::ffff:192.0.2.1]"
Γ£ô IPv6 with compression: "user@[2001:db8:85a3::8a2e:370:7334]"
Γ£ô IPv6 full form: "user@[2001:0db8:0000:0000:0000:ff00:0042:8329]"
Γ£ô Subdomain + country TLD: "first.last@sub.domain.co.uk"
Γ£ô Hyphen in domain: "user@domain-name.com"
Γ£ô Numeric domain labels: "user@123.456.789.012"
Γ£ô Single-char TLD: "user@domain.x"
Γ£ô Numeric TLD: "user@domain.123"
Γ£ô Consecutive dots in local: "user..double@domain.com"
Γ£ô Starts with dot: ".user@domain.com"
Γ£ô Ends with dot: "user.@domain.com"
Γ£ô Consecutive dots in domain: "user@domain..com"
Γ£ô Missing local part: "@example.com"
Γ£ô Missing domain: "user@"
Γ£ô Missing @: "userexample.com"
Γ£ô Double @: "user@@example.com"
Γ£ô Missing TLD: "user@domain"
Γ£ô Domain starts with dot: "user@.domain.com"
Γ£ô Domain ends with dot: "user@domain.com."
Γ£ô Domain label starts with hyphen: "user@-domain.com"
Γ£ô Domain label ends with hyphen: "user@domain-.com"
Γ£ô Unquoted space: "user name@example.com"
Γ£ô Space in domain: "user@domain .com"
Γ£ô Unclosed quote: ""unclosed@example.com"
Γ£ô Quote in middle without @: ""user"name@example.com"
Γ£ô Invalid IPv4 (3 octets): "user@[192.168.1]"
Γ£ô Invalid IPv4 (octet > 255): "user@[999.168.1.1]"
Γ£ô Invalid IPv4 (octet = 256): "user@[192.168.1.256]"
Γ£ô Invalid IPv6 (bad hex): "user@[gggg::1]"

Result: 64/64 passed (100%)

======================================================================

=== TEXT SCANNING (Content Detection) ===
Conservative validation for PII detection

Γ£ô Email in sentence
  Input: "Contact us at support@company.com for help"
  Found: support@company.com

Γ£ô Multiple emails
  Input: "Send to: user@example.com, admin@test.org"
  Found: user@example.com admin@test.org

Γ£ô After colon
  Input: "Email: test@domain.co.uk"
  Found: test@domain.co.uk

Γ£ô In angle brackets
  Input: "<user@example.com>"
  Found: user@example.com

Γ£ô In parentheses
  Input: "(contact: admin@site.com)"
  Found: admin@site.com

Γ£ô Apostrophe blocks extraction
  Input: "That's john'semail@example.com works"

Γ£ô % blocks extraction
  Input: "user%test@domain.com"

Γ£ô ! blocks extraction
  Input: "user!name@test.com"

Γ£ô # blocks extraction
  Input: "user#admin@example.com"

Γ£ô IP literal in scan mode
  Input: "Server: user@[192.168.1.1]"

Γ£ô Consecutive dots
  Input: "user..double@domain.com"

Γ£ô No TLD
  Input: "test@domain"

Γ£ô Starts with dot
  Input: ".user@domain.com"

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

Result: 17/17 passed (100%)

======================================================================

=== EMAIL DETECTION TEST ===
Testing both exact validation and text scanning

SENSITIVE: "Simple email: user@example.com in text"
  => Found emails: user@example.com

SENSITIVE: "Multiple emails: first@domain.com and second@another.org"
  => Found emails: first@domain.com second@another.org

CLEAN    : "user..double@domain.com"

SENSITIVE: "Complex: john.doe+filter@sub.domain.co.uk mixed with text"
  => Found emails: john.doe+filter@sub.domain.co.uk

CLEAN    : "No emails in this text at all"

SENSITIVE: "Edge case: a@b.co minimal email"
  => Found emails: a@b.co

SENSITIVE: "review-team@geeksforgeeks.org"
  => Found emails: review-team@geeksforgeeks.org

CLEAN    : "user..double@domain.com"

CLEAN    : "user.@domain.com"

SENSITIVE: "27 age and alpha@gmail.com and other data"
  => Found emails: alpha@gmail.com

SENSITIVE: "adfdgifldj@fk458439678 4krf8956 346 alpha@gmail.com r90wjk kf433@8958ifdjkks fgkl548765gr"
  => Found emails: alpha@gmail.com

SENSITIVE: "27 age and alphatyicbnkdleoxkthes123fd56569565@gmail.com and othere data missing...!"
  => Found emails: alphatyicbnkdleoxkthes123fd56569565@gmail.com

CLEAN    : "any aged group and alphatyic(b)nkdleoxk%t/hes123fd56569565@gmail.com and othere data missing...!"

SENSITIVE: "27 age and alphatyicbnk.?'.,dleoxkthes123fd56569565@gmail.com and othere data missing...! other@email.co"
  => Found emails: dleoxkthes123fd56569565@gmail.com other@email.co

CLEAN    : "27 age and alphatyicbnkdleo$#-=+xkthes123fd56569565@gmail.com and othere data missing...!"

CLEAN    : "No email here"

CLEAN    : "test@domain"

CLEAN    : "invalid@.com"

SENSITIVE: "valid.email+tag@example.co.uk"
  => Found emails: valid.email+tag@example.co.uk

SENSITIVE: "Contact us at support@company.com for help"
  => Found emails: support@company.com

SENSITIVE: "Multiple: first@test.com, second@demo.org"
  => Found emails: first@test.com second@demo.org

CLEAN    : "invalid@.com and test@domain"

CLEAN    : "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxhidden@email.comyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"

SENSITIVE: "user@example.com"
  => Found emails: user@example.com

SENSITIVE: "a@b.co"
  => Found emails: a@b.co

SENSITIVE: "test.user@example.com"
  => Found emails: test.user@example.com

SENSITIVE: "user+tag@gmail.com"
  => Found emails: user+tag@gmail.com

CLEAN    : "user!test@example.com"

CLEAN    : "user#tag@example.com"

CLEAN    : "user$admin@example.com"

CLEAN    : "user%percent@example.com"

CLEAN    : "user&name@example.com"

CLEAN    : "user'quote@example.com"

CLEAN    : "user*star@example.com"

CLEAN    : "user=equal@example.com"

CLEAN    : "user?question@example.com"

CLEAN    : "user^caret@example.com"

SENSITIVE: "user_underscore@example.com"
  => Found emails: user_underscore@example.com

CLEAN    : "user`backtick@example.com"

SENSITIVE: "userbrace@example.com"
  => Found emails: userbrace@example.com

CLEAN    : "user|pipe@example.com"

CLEAN    : "user}brace@example.com"

CLEAN    : "user~tilde@example.com"

CLEAN    : ""user"@example.com"

CLEAN    : ""user name"@example.com"

CLEAN    : ""user@internal"@example.com"

CLEAN    : ""user.name"@example.com"

CLEAN    : ""user\"name"@example.com"

CLEAN    : ""user\\name"@example.com"

CLEAN    : "user@[192.168.1.1]"

CLEAN    : "user@[2001:db8::1]"

CLEAN    : "test@[10.0.0.1]"

CLEAN    : "user@[fe80::1]"

CLEAN    : "user@[::1]"

SENSITIVE: "first.last@sub.domain.co.uk"
  => Found emails: first.last@sub.domain.co.uk

SENSITIVE: "user@domain-name.com"
  => Found emails: user@domain-name.com

SENSITIVE: "user@123.456.789.012"
  => Found emails: user@123.456.789.012

SENSITIVE: "user@domain.x"
  => Found emails: user@domain.x

SENSITIVE: "user@domain.123"
  => Found emails: user@domain.123

CLEAN    : "user..double@domain.com"

CLEAN    : ".user@domain.com"

CLEAN    : "user.@domain.com"

CLEAN    : "user@domain..com"

CLEAN    : "@example.com"

CLEAN    : "user@"

CLEAN    : "userexample.com"

CLEAN    : "user@@example.com"

CLEAN    : "user@domain"

CLEAN    : "user@.domain.com"

SENSITIVE: "user@domain.com."
  => Found emails: user@domain.com

CLEAN    : "user@-domain.com"

CLEAN    : "user@domain-.com"

SENSITIVE: "user name@example.com"
  => Found emails: name@example.com

CLEAN    : "user@domain .com"

CLEAN    : ""unclosed@example.com"

CLEAN    : ""user"name@example.com"

CLEAN    : "user@[192.168.1]"

CLEAN    : "user@[999.168.1.1]"

CLEAN    : "user@[192.168.1.256]"

CLEAN    : "user@[gggg::1]"

======================================================================
Γ£ô Email Detection Complete
======================================================================
=== PERFORMANCE BENCHMARK ===
Threads: 16
Iterations per thread: 100000
Total operations: 128000000
Time: 2030 ms
Ops/sec: 63054187
Validations: 80000000

======================================================================
Γ£ô 100% RFC 5322 COMPLIANT
Γ£ô SOLID Principles Applied
Γ£ô Thread-Safe Implementation
Γ£ô Production-Ready Performance
======================================================================

Features:
  ΓÇó Quoted strings: "user name"@example.com
  ΓÇó IP literals: user@[192.168.1.1] (exact mode only)
  ΓÇó All RFC 5322 special characters
  ΓÇó Alphanumeric TLDs
  ΓÇó Single-character TLDs
  ΓÇó Conservative text scanning (strict boundaries)
  ΓÇó Proper word boundary detection (no false positives)
======================================================================
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
