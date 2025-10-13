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
g++ -O3 -march=native -flto=auto -DNDEBUG -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
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
g++ -g -std=c++17 -pthread EmailDetector.cpp -o EmailDetector
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

Result: 63/63 passed (100%)

======================================================================

=== TEXT SCANNING (Content Detection) ===
Conservative validation for PII detection

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

Γ£ô Only dots before @
  Input: "user...@domain.com"

Γ£ô @ at the end
  Input: "user@domain.com@"
  Found: user@domain.com

Γ£ô Find the alphabet or dight if any invalid special character found before @
  Input: "27 age and !-+alphatyicbnkdleo$#-=+xkthes123fd56569565@somedomain.com and othere data missing...!"
  Found: alphatyicbnkdleo$#-=+xkthes123fd56569565@somedomain.com

Γ£ô Find the alphabet or dight if any invalid special character found before @
  Input: "27 age and alphatyicbnkdleo$#-=+xkthes?--=:-+123fd56569565@gmail.co.uk and othere data missing...!"
  Found: 123fd56569565@gmail.co.uk

Γ£ô Find the alphabet or dight if any invalid special character found before @
  Input: "27 age and alphatyicbnk.?'.,dleoxkthes123fd56569565@gmail.com and othere data missing...! other@email.co.in"
  Found: dleoxkthes123fd56569565@gmail.com other@email.co.in

Γ£ô Find the alphabet or dight if any invalid special character found before @ if no alphabet found then consider legal special character
  Input: "27 age and alphatyicbnk.?'.::++--%@somedomain.co.uk and othere data missing...! other@email.co.in"
  Found: ++--%@somedomain.co.uk other@email.co.in

Γ£ô ! before @ is legal according to RFC rule
  Input: "user!@domain.com"
  Found: user!@domain.com

Γ£ô # before @ is legal according to RFC rule
  Input: "user#@domain.com"
  Found: user#@domain.com

Γ£ô $ before @ is legal according to RFC rule
  Input: "user$@domain.com"
  Found: user$@domain.com

Γ£ô % before @ is legal according to RFC rule
  Input: "user%@domain.com"
  Found: user%@domain.com

Γ£ô & before @ is legal according to RFC rule
  Input: "user&@domain.com"
  Found: user&@domain.com

Γ£ô ' before @ is legal according to RFC rule
  Input: "user'@domain.com"
  Found: user'@domain.com

Γ£ô * before @ is legal according to RFC rule
  Input: "user*@domain.com"
  Found: user*@domain.com

Γ£ô + before @ is legal according to RFC rule
  Input: "user+@domain.com"
  Found: user+@domain.com

Γ£ô - before @ is legal according to RFC rule
  Input: "user-@domain.com"
  Found: user-@domain.com

Γ£ô / before @ is legal according to RFC rule
  Input: "user/@domain.com"
  Found: user/@domain.com

Γ£ô = before @ is legal according to RFC rule
  Input: "user=@domain.com"
  Found: user=@domain.com

Γ£ô ? before @ is legal according to RFC rule
  Input: "user?@domain.com"
  Found: user?@domain.com

Γ£ô ^ before @ is legal according to RFC rule
  Input: "user^@domain.com"
  Found: user^@domain.com

Γ£ô _ before @ is legal according to RFC rule
  Input: "user_@domain.com"
  Found: user_@domain.com

Γ£ô ` before @ is legal according to RFC rule
  Input: "user`@domain.com"
  Found: user`@domain.com

Γ£ô { before @ is legal according to RFC rule
  Input: "user{@domain.com"
  Found: user{@domain.com

Γ£ô | before @ is legal according to RFC rule
  Input: "user|@domain.com"
  Found: user|@domain.com

Γ£ô } before @ is legal according to RFC rule
  Input: "user}@domain.com"
  Found: user}@domain.com

Γ£ô ~ before @ is legal according to RFC rule
  Input: "user~@domain.com"
  Found: user~@domain.com

Γ£ô space before @ is illegal in an unquoted local-part
  Input: "user @domain.com"

Γ£ô " (double quote) is illegal unless the entire local-part is a quoted-string (e.g. "...")
  Input: "user"@domain.com"

Γ£ô ( before @ is illegal in an unquoted local-part (parentheses used for comments)
  Input: "user(@domain.com"

Γ£ô ) before @ is illegal in an unquoted local-part (parentheses used for comments)
  Input: "user)@domain.com"

Γ£ô , before @ is illegal in an unquoted local-part
  Input: "user,@domain.com"

Γ£ô : before @ is illegal in an unquoted local-part
  Input: "user:@domain.com"

Γ£ô ; before @ is illegal in an unquoted local-part
  Input: "user;@domain.com"

Γ£ô < before @ is illegal in an unquoted local-part
  Input: "user<@domain.com"

Γ£ô > before @ is illegal in an unquoted local-part
  Input: "user>@domain.com"

Γ£ô \ (backslash) is illegal unquoted; allowed only inside quoted-strings as an escape
  Input: "user\@domain.com"

Γ£ô [ before @ is illegal in an unquoted local-part
  Input: "user[@domain.com"

Γ£ô ] before @ is illegal in an unquoted local-part
  Input: "user]@domain.com"

Γ£ô additional @ inside the local-part is illegal (only one @ separates local and domain)
  Input: "user@@domain.com"

Γ£ô trailing dot in local-part is illegal (dot cannot start or end the local-part)
  Input: "user.@domain.com"

Γ£ô CR (carriage return) is illegal (control characters are not allowed)
@domain.com"er

Γ£ô LF (line feed/newline) is illegal (control characters are not allowed)
  Input: "user
@domain.com"

Γ£ô TAB is illegal (control/whitespace characters are not allowed)
  Input: "user  @domain.com"

Γ£ô '!' before @ is legal (atext); second local-part is 'com!' which is RFC-valid
  Input: "text123@user.com!@domain.in"
  Found: text123@user.com user.com!@domain.in

Γ£ô '#' before @ is legal (atext); second local-part is 'com#' which is RFC-valid
  Input: "123text@user.com#@domain.in"
  Found: 123text@user.com user.com#@domain.in

Γ£ô '$' before @ is legal (atext); second local-part is 'com$' which is RFC-valid
  Input: "365text@user.com$@domain.in"
  Found: 365text@user.com user.com$@domain.in

Γ£ô '%' before @ is legal (atext); second local-part is 'com%' which is RFC-valid
  Input: "text@user.com%@domain.in"
  Found: text@user.com user.com%@domain.in

Γ£ô '&' before @ is legal (atext); second local-part is 'com&' which is RFC-valid
  Input: "text@user.com&@domain.in"
  Found: text@user.com user.com&@domain.in

Γ£ô ''' before @ is legal (atext); second local-part is "com'" which is RFC-valid
  Input: "text@user.com'@domain.in"
  Found: text@user.com user.com'@domain.in

Γ£ô '*' before @ is legal (atext); second local-part is 'com*' which is RFC-valid
  Input: "text@user.com*@domain.in"
  Found: text@user.com user.com*@domain.in

Γ£ô '+' before @ is legal (atext); second local-part is 'com+' which is RFC-valid
  Input: "text@user.com+@domain.in"
  Found: text@user.com user.com+@domain.in

Γ£ô '-' before @ is legal (atext); second local-part is 'com-' which is RFC-valid
  Input: "text@user.com-@domain.in"
  Found: text@user.com user.com-@domain.in

Γ£ô '/' before @ is legal (atext); second local-part is 'com/' which is RFC-valid
  Input: "text@user.com/@domain.in"
  Found: text@user.com user.com/@domain.in

Γ£ô '=' before @ is legal (atext); second local-part is 'com=' which is RFC-valid
  Input: "text@user.com=@domain.in"
  Found: text@user.com user.com=@domain.in

Γ£ô '?' before @ is legal (atext); second local-part is 'com?' which is RFC-valid
  Input: "text@user.com?@domain.in"
  Found: text@user.com user.com?@domain.in

Γ£ô '^' before @ is legal (atext); second local-part is 'com^' which is RFC-valid
  Input: "text@user.com^@domain.in"
  Found: text@user.com user.com^@domain.in

Γ£ô '_' before @ is legal (atext); second local-part is 'com_' which is RFC-valid
  Input: "text@user.com_@domain.in"
  Found: text@user.com user.com_@domain.in

Γ£ô '`' before @ is legal (atext); second local-part is 'com`' which is RFC-valid
  Input: "text@user.com`@domain.in"
  Found: text@user.com user.com`@domain.in

Γ£ô '{' before @ is legal (atext); second local-part is 'com{' which is RFC-valid
  Input: "text@user.com{@domain.in"
  Found: text@user.com user.com{@domain.in

Γ£ô '|' before @ is legal (atext); second local-part is 'com|' which is RFC-valid
  Input: "text@user.com|@domain.in"
  Found: text@user.com user.com|@domain.in

Γ£ô '}' before @ is legal (atext); second local-part is 'com}' which is RFC-valid
  Input: "text@user.com}@domain.in"
  Found: text@user.com user.com}@domain.in

Γ£ô '~' before @ is legal (atext); second local-part is 'com~' which is RFC-valid
  Input: "text@user.com~@domain.in"
  Found: text@user.com user.com~@domain.in

Γ£ô '!!' before @ is legal (atext); second local-part is 'com!' which is RFC-valid
  Input: "text@user.com!!@domain.in"
  Found: text@user.com user.com!!@domain.in

Γ£ô '##' before @ is legal (atext); second local-part is 'com#' which is RFC-valid
  Input: "text@user.com##@domain.in"
  Found: text@user.com user.com##@domain.in

Γ£ô '$$' before @ is legal (atext); second local-part is 'com$' which is RFC-valid
  Input: "text@user.com$$@domain.in"
  Found: text@user.com user.com$$@domain.in

Γ£ô '%%' before @ is legal (atext); second local-part is 'com%' which is RFC-valid
  Input: "text@user.com%%@domain.in"
  Found: text@user.com user.com%%@domain.in

Γ£ô '&&' before @ is legal (atext); second local-part is 'com&' which is RFC-valid
  Input: "text@user.com&&@domain.in"
  Found: text@user.com user.com&&@domain.in

Γ£ô '''' before @ is legal (atext); second local-part is "com'" which is RFC-valid
  Input: "text@user.com''@domain.in"
  Found: text@user.com user.com''@domain.in

Γ£ô '**' before @ is legal (atext); second local-part is 'com*' which is RFC-valid
  Input: "text@user.com**@domain.in"
  Found: text@user.com user.com**@domain.in

Γ£ô '++' before @ is legal (atext); second local-part is 'com+' which is RFC-valid
  Input: "text@user.com++@domain.in"
  Found: text@user.com user.com++@domain.in

Γ£ô '--' before @ is legal (atext); second local-part is 'com-' which is RFC-valid
  Input: "text@user.com--@domain.in"
  Found: text@user.com user.com--@domain.in

Γ£ô '//' before @ is legal (atext); second local-part is 'com/' which is RFC-valid
  Input: "text@user.com//@domain.in"
  Found: text@user.com user.com//@domain.in

Γ£ô '==' before @ is legal (atext); second local-part is 'com=' which is RFC-valid
  Input: "text@user.com==@domain.in"
  Found: text@user.com user.com==@domain.in

Γ£ô '??' before @ is legal (atext); second local-part is 'com?' which is RFC-valid
  Input: "text@user.com??@domain.in"
  Found: text@user.com user.com??@domain.in

Γ£ô '^^' before @ is legal (atext); second local-part is 'com^' which is RFC-valid
  Input: "text@user.com^^@domain.in"
  Found: text@user.com user.com^^@domain.in

Γ£ô '__' before @ is legal (atext); second local-part is 'com_' which is RFC-valid
  Input: "text@user.com__@domain.in"
  Found: text@user.com user.com__@domain.in

Γ£ô '``' before @ is legal (atext); second local-part is 'com`' which is RFC-valid
  Input: "text@user.com``@domain.in"
  Found: text@user.com user.com``@domain.in

Γ£ô '{{' before @ is legal (atext); second local-part is 'com{' which is RFC-valid
  Input: "text@user.com{{@domain.in"
  Found: text@user.com user.com{{@domain.in

Γ£ô '||' before @ is legal (atext); second local-part is 'com|' which is RFC-valid
  Input: "text@user.com||@domain.in"
  Found: text@user.com user.com||@domain.in

Γ£ô '}}' before @ is legal (atext); second local-part is 'com}' which is RFC-valid
  Input: "text@user.com}}@domain.in"
  Found: text@user.com user.com}}@domain.in

Γ£ô '~~' before @ is legal (atext); second local-part is 'com~' which is RFC-valid
  Input: "text@user.com~~@domain.in"
  Found: text@user.com user.com~~@domain.in

Γ£ô space before @ is illegal in unquoted local-part
  Input: "text@user.com @domain.in"
  Found: text@user.com

Γ£ô " (double quote) is illegal unless the local-part is fully quoted
  Input: "text@user.com"@domain.in"
  Found: text@user.com

Γ£ô '(' before @ is illegal (parentheses denote comments)
  Input: "text@user.com(@domain.in"
  Found: text@user.com

Γ£ô ')' before @ is illegal (parentheses denote comments)
  Input: "text@user.com)@domain.in"
  Found: text@user.com

Γ£ô ',' before @ is illegal in an unquoted local-part
  Input: "text@user.com,@domain.in"
  Found: text@user.com

Γ£ô ':' before @ is illegal in an unquoted local-part
  Input: "text@user.com:@domain.in"
  Found: text@user.com

Γ£ô ';' before @ is illegal in an unquoted local-part
  Input: "text@user.com;@domain.in"
  Found: text@user.com

Γ£ô '<' before @ is illegal in an unquoted local-part
  Input: "text@user.com<@domain.in"
  Found: text@user.com

Γ£ô '>' before @ is illegal in an unquoted local-part
  Input: "text@user.com>@domain.in"
  Found: text@user.com

Γ£ô '\' is illegal unless used inside a quoted-string (escaped)
  Input: "text@user.com\@domain.in"
  Found: text@user.com

Γ£ô '[' before @ is illegal in an unquoted local-part
  Input: "text@user.com[@domain.in"
  Found: text@user.com

Γ£ô ']' before @ is illegal in an unquoted local-part
  Input: "text@user.com]@domain.in"
  Found: text@user.com

Γ£ô double '@' is illegal ΓÇö only one @ allowed per address
  Input: "text@user.com@@domain.in"
  Found: text@user.com

Γ£ô dot cannot appear at the end of the local-part (illegal trailing dot)
  Input: "text@user.com.@domain.in"
  Found: text@user.com

Γ£ô carriage return (CR) is illegal ΓÇö control characters not allowed
@domain.in"ext@user.com
  Found: text@user.com

Γ£ô line feed (LF) is illegal ΓÇö control characters not allowed
  Input: "text@user.com
@domain.in"
  Found: text@user.com

Γ£ô horizontal tab (TAB) is illegal ΓÇö whitespace not allowed
  Input: "text@user.com @domain.in"
  Found: text@user.com

Γ£ô Each local-part contains valid atext characters ('#', '!') before '@' ΓÇö all RFC 5322 compliant
  Input: "In this paragraph there are some emails first@domain.com#@second!@test.org!@alpha.in please find out them...!"
  Found: first@domain.com second!@test.org test.org!@alpha.in

Γ£ô Multiple addresses joined; '+', '$' are legal atext characters in local-part
  Input: "In this paragraph there are some emails alice@company.net+@bob$@service.co$@example.org please find out them...!"
  Found: alice@company.net bob$@service.co service.co$@example.org

Γ£ô Each local-part uses legal atext chars ('*', '#', '-') before '@'
  Input: "In this paragraph there are some emails one.user@site.com*@two#@host.org*@third-@example.io please find out them...!"
  Found: one.user@site.com two#@host.org third-@example.io

Γ£ô Double consecutive legal characters ('!!', '##', '$$') are RFC-valid though uncommon
  Input: "In this paragraph there are some emails foo@bar.com!!@baz##@qux$$@quux.in please find out them...!"
  Found: foo@bar.com qux$$@quux.in

Γ£ô Mix of valid symbols '+', '*', '/', '-' in local-parts ΓÇö all atext-legal
  Input: "In this paragraph there are some emails alpha@beta.com+*@gamma/delta.com+*@eps-@zeta.co please find out them...!"
  Found: alpha@beta.com eps-@zeta.co

Γ£ô Local-parts include '^', '_', '`', '{' ΓÇö all RFC-allowed characters
  Input: "In this paragraph there are some emails u1@d1.org^@u2_@d2.net`@u3{@d3.io please find out them...!"
  Found: u1@d1.org u2_@d2.net u3{@d3.io

Γ£ô Legal special chars ('|', '~') appear before '@' ΓÇö still RFC-valid
  Input: "In this paragraph there are some emails name@dom.com|@name2@dom2.com|@name3~@dom3.org please find out them...!"
  Found: name@dom.com name2@dom2.com name3~@dom3.org

Γ£ô Combination of '-', '+', '*' in local-part are permitted under RFC 5322
  Input: "In this paragraph there are some emails me.last@my.org-@you+@your.org-@them*@their.io please find out them...!"
  Found: me.last@my.org you+@your.org them*@their.io

Γ£ô Chained valid addresses with '=', '#', '$', '%' ΓÇö all within atext definition
  Input: "In this paragraph there are some emails p@q.com=@r#@s$@t%u.org please find out them...!"
  Found: p@q.com

Γ£ô Valid plus, dash, and tilde used before '@'; RFC 5322-legal though rarely used
  Input: "In this paragraph there are some emails first@domain.com++@second@test.org--@alpha~~@beta.in please find out them...!"
  Found: first@domain.com second@test.org alpha~~@beta.in

Γ£ô Valid plus, dash, and tilde used before '@'; RFC 5322-legal though rarely used
  Input: "In this paragraph there are some emails first@domain.com++@second@@test.org--@alpha~~@beta.in please find out them...!"
  Found: first@domain.com alpha~~@beta.in

Γ£ô Consecutive dots (standalone)
  Input: "user..name@domain.com"
  Found: name@domain.com

Γ£ô Consecutive dots (in text)
  Input: "text user..name@domain.com text"
  Found: name@domain.com

Γ£ô Dot before @
  Input: "text username.@domain.com text"

Γ£ô Dot-hyphen sequence
  Input: "user.-name@domain.com"
  Found: user.-name@domain.com

Γ£ô Hyphen-dot sequence
  Input: "user-.name@domain.com"
  Found: user-.name@domain.com

Γ£ô Dot-plus sequence
  Input: "user.+name@domain.com"
  Found: user.+name@domain.com

Γ£ô Plus-dot sequence
  Input: "user+.name@domain.com"
  Found: user+.name@domain.com

Γ£ô Plus-hyphen combo
  Input: "user+-name@domain.com"
  Found: user+-name@domain.com

Γ£ô Hyphen-plus combo
  Input: "user-+name@domain.com"
  Found: user-+name@domain.com

Γ£ô Underscore-hyphen
  Input: "user_-name@domain.com"
  Found: user_-name@domain.com

Γ£ô Dot-underscore
  Input: "user._name@domain.com"
  Found: user._name@domain.com

Γ£ô Multiple special chars in middle
  Input: "user#$%name@domain.com"
  Found: user#$%name@domain.com

Γ£ô Hash-dot combo
  Input: "user#.name@domain.com"
  Found: user#.name@domain.com

Γ£ô Dot-hash combo
  Input: "user.#name@domain.com"
  Found: user.#name@domain.com

Γ£ô Semicolon terminator
  Input: "Email:user@domain.com;note"
  Found: user@domain.com

Γ£ô Bracket terminators
  Input: "List[user@domain.com]end"
  Found: user@domain.com

Γ£ô Parenthesis terminators
  Input: "Text(user@domain.com)more"
  Found: user@domain.com

Γ£ô Angle bracket terminators
  Input: "Start<user@domain.com>end"
  Found: user@domain.com

Γ£ô Double quote terminators
  Input: "Start"user@domain.com"end"
  Found: user@domain.com

Γ£ô Single quote terminators
  Input: "Start'user@domain.com'end"
  Found: user@domain.com

Γ£ô ` terminators
  Input: "Start`user@domain.com`end"
  Found: user@domain.com

Γ£ô Single $ prefix
  Input: "$user@domain.com"
  Found: $user@domain.com

Γ£ô Double $ prefix
  Input: "$$user@domain.com"
  Found: $$user@domain.com

Γ£ô Mixed special prefix
  Input: "$#!user@domain.com"
  Found: $#!user@domain.com

Γ£ô Standalone dot prefix will be treamed
  Input: ".user@domain.com"
  Found: user@domain.com

Γ£ô Space then dot prefix
  Input: "text .user@domain.com"
  Found: user@domain.com

Γ£ô Double @ (invalid)
  Input: "user@@domain.com"

Γ£ô @ in domain (invalid)
  Input: "user@domain@com"

Γ£ô Multiple @ in sequence
  Input: "first@domain.com@second@test.org"
  Found: first@domain.com second@test.org

Γ£ô Two valid separate emails
  Input: "user@domain.com then admin@test.org"
  Found: user@domain.com admin@test.org

Γ£ô Local part too long (>64)
  Input: "axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@domain.com"

Γ£ô Long part after skip
  Input: "prefix###xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@domain.com"

Γ£ô Exactly 64 chars (valid)
  Input: "xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@domain.com"
  Found: xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@domain.com

Γ£ô Leading hyphen in local (allowed in scan)
  Input: "-user@domain.com"
  Found: -user@domain.com

Γ£ô Trailing hyphen in local
  Input: "user-@domain.com"
  Found: user-@domain.com

Γ£ô Multiple hyphens
  Input: "u-s-e-r@domain.com"
  Found: u-s-e-r@domain.com

Γ£ô Consecutive hyphens
  Input: "user---name@domain.com"
  Found: user---name@domain.com

Γ£ô Single char subdomain
  Input: "user@d.co"
  Found: user@d.co

Γ£ô Single char TLD
  Input: "user@domain.c"
  Found: user@domain.c

Γ£ô Numeric TLD
  Input: "user@domain.123"
  Found: user@domain.123

Γ£ô Multiple subdomains
  Input: "user@sub.domain.co.uk"
  Found: user@sub.domain.co.uk

Γ£ô All numeric domain
  Input: "user@123.456.789.012"
  Found: user@123.456.789.012

Γ£ô Missing TLD
  Input: "user@domain"

Γ£ô Trailing dot in domain
  Input: "user@domain."

Γ£ô Leading dot in domain
  Input: "user@.domain.com"

Γ£ô Consecutive dots in domain
  Input: "user@domain..com"

Γ£ô Leading hyphen in domain label
  Input: "user@-domain.com"

Γ£ô Trailing hyphen in domain label
  Input: "user@domain-.com"

Γ£ô Space before @
  Input: "user @domain.com"

Γ£ô Space after @
  Input: "user@ domain.com"

Γ£ô Space in domain
  Input: "user@domain .com"

Γ£ô Tab before @
  Input: "user  @domain.com"

Γ£ô Newline after email
  Input: "user@domain.com
text"
  Found: user@domain.com

Γ£ô Two minimal emails
  Input: "Emails: a@b.co, x@y.org"
  Found: a@b.co x@y.org

Γ£ô Plus addressing
  Input: "Contact: user+tag@site.com"
  Found: user+tag@site.com

Γ£ô Underscore in local
  Input: "Reply to user_name@example.com."
  Found: user_name@example.com

Γ£ô Equals before email
  Input: "value=user@domain.com"
  Found: value=user@domain.com

Γ£ô Dollar with digits prefix
  Input: "price$100user@domain.com"
  Found: price$100user@domain.com

Γ£ô Percent after digit
  Input: "50%user@domain.com"
  Found: 50%user@domain.com

Γ£ô Hash in middle with digit
  Input: "user#1@domain.com"
  Found: user#1@domain.com

Γ£ô Double dot prefix
  Input: "..user@domain.com"
  Found: user@domain.com

Γ£ô Double dot suffix
  Input: "user..@domain.com"

Γ£ô Dots at both ends
  Input: ".user.@domain.com"

Γ£ô Plus at end of local
  Input: "user+@domain.com"
  Found: user+@domain.com

Γ£ô Plus at start of local
  Input: "+user@domain.com"
  Found: +user@domain.com

Γ£ô Consecutive plus signs
  Input: "user++tag@domain.com"
  Found: user++tag@domain.com

Γ£ô Multiple plus tags
  Input: "user+tag+extra@domain.com"
  Found: user+tag+extra@domain.com

Γ£ô Many single char segments
  Input: "u.s.e.r@domain.com"
  Found: u.s.e.r@domain.com

Γ£ô Dot immediately before @
  Input: "user.@domain.com"

Γ£ô Dot before @ in text
  Input: "text user.@domain.com"

Γ£ô IPv4 literal (scan mode)
  Input: "user@[192.168.1.1]"

Γ£ô IPv6 literal (scan mode)
  Input: "user@[::1]"

Γ£ô IPv4 in text (scan mode)
  Input: "text user@[10.0.0.1] more"

Γ£ô Minimal valid email
  Input: "a@b.co"
  Found: a@b.co

Γ£ô Minimal with single char TLD
  Input: "a@b.c"
  Found: a@b.c

Γ£ô Two char everything
  Input: "ab@cd.ef"
  Found: ab@cd.ef

Γ£ô All numeric local
  Input: "123@domain.com"
  Found: 123@domain.com

Γ£ô Numeric subdomain
  Input: "user@123.com"
  Found: user@123.com

Γ£ô Numbers everywhere
  Input: "user123@domain456.com789"
  Found: user123@domain456.com789

Γ£ô Starting with number
  Input: "2user@domain.com"
  Found: 2user@domain.com

Γ£ô Mixed case (preserved)
  Input: "User@Domain.COM"
  Found: User@Domain.COM

Γ£ô All uppercase
  Input: "USER@DOMAIN.COM"
  Found: USER@DOMAIN.COM

Γ£ô Hash prefix
  Input: "###user@domain.com"
  Found: ###user@domain.com

Γ£ô Dollar prefix
  Input: "$$$user@domain.com"
  Found: $$$user@domain.com

Γ£ô Exclamation prefix
  Input: "!!!user@domain.com"
  Found: !!!user@domain.com

Γ£ô Hash in middle
  Input: "user###name@domain.com"
  Found: user###name@domain.com

Γ£ô Just @ symbol
  Input: "@"

Γ£ô Double @ only
  Input: "@@"

Γ£ô Missing domain entirely
  Input: "user@"

Γ£ô Missing local entirely
  Input: "@domain.com"

Γ£ô Money then comma then contact: extract user@domain.com
  Input: "price=$19.99,contact:user@domain.com"
  Found: user@domain.com

Γ£ô Single-quoted around canonical address ΓÇö extract inner address
  Input: "email='user@domain.com'"
  Found: user@domain.com

Γ£ô Single-quote in local-part is atext; whole token is RFC-5322 valid
  Input: "email='alpha@domin.co.uk"
  Found: email='alpha@domin.co.uk

Γ£ô Double-quoted canonical address ΓÇö extract inner address
  Input: "user="alpha@domin.co.uk""
  Found: alpha@domin.co.uk

Γ£ô Heuristic extraction: prefer an address that starts with an alphabet/digit before '@' if any invalid special character found in the text; if none found, accept a local-part made only of valid atext special characters
  Input: "user="alpha@domin.co.uk"
  Found: alpha@domin.co.uk

Γ£ô Backtick-delimited address ΓÇö extract inner address
  Input: "user=`alpha@domin.co.uk`"
  Found: alpha@domin.co.uk

Γ£ô Unclosed backtick is atext; whole token is RFC-5322 valid
  Input: "user=`alpha@domin.co.uk"
  Found: user=`alpha@domin.co.uk

Γ£ô Heuristic extraction: prefer an address that starts with an alphabet/digit before '@' if any invalid special character found in the text; if none found, accept a local-part made only of valid atext special characters
  Input: "mailto:user@domain.com"
  Found: user@domain.com

Γ£ô Heuristic extraction: prefer an address that starts with an alphabet/digit before '@' if any invalid special character found in the text; if none found, accept a local-part made only of valid atext special characters
  Input: "http://user@domain.com"
  Found: user@domain.com

Γ£ô heuristic: double-quoted canonical address ΓÇö extract inner address
  Input: "user=\"alpha@domin.co.uk\""
  Found: alpha@domin.co.uk

Γ£ô heuristic: unclosed double-quote ΓÇö prefer alnum-start local-part; fallback to atext-only local
  Input: "user=\"alpha@domin.co.uk"
  Found: alpha@domin.co.uk

Γ£ô Plus-hyphen combo
  Input: "user+-name@domain.com"
  Found: user+-name@domain.com

Γ£ô Hyphen-plus combo
  Input: "user-+name@domain.com"
  Found: user-+name@domain.com

Γ£ô Underscore-hyphen
  Input: "user_-name@domain.com"
  Found: user_-name@domain.com

Γ£ô Dot-underscore
  Input: "user._name@domain.com"
  Found: user._name@domain.com

Γ£ô Unicode in local part
  Input: "user╬ô├æ├│@domain.com"

Γ£ô Unicode in domain
  Input: "user@domain╬ô├æ├│.com"

Γ£ô Unicode in TLD
  Input: "user@domain.cΓö£Γûôm"

Γ£ô Email in sentence
  Input: "Contact us at support@company.co.in for help"
  Found: support@company.co.in

Γ£ô Multiple emails
  Input: "Send to: user@example.com, admin@test.co.org"
  Found: user@example.com admin@test.co.org

Γ£ô After colon
  Input: "Email: test@domain.co.uk"
  Found: test@domain.co.uk

Γ£ô In angle brackets
  Input: "<user@example.co.in>"
  Found: user@example.co.in

Γ£ô In parentheses
  Input: "(contact: admin@site.co.uk)"
  Found: admin@site.co.uk

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

Result: 233/233 passed (100%)

======================================================================

=== EMAIL DETECTION TEST ===
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

SENSITIVE: "user..double@domain.com"
  => Found emails: double@domain.com

CLEAN    : "user.@domain.com"

SENSITIVE: "27 age and alpha@gmail.com and other data"
  => Found emails: alpha@gmail.com

SENSITIVE: "adfdgifldj@fk458439678 4krf8956 346 alpha@gmail.com r90wjk kf433@8958ifdjkks fgkl548765gr"
  => Found emails: alpha@gmail.com

SENSITIVE: "27 age and alphatyicbnkdleoxkthes123fd56569565@gmail.com and othere data missing...!"
  => Found emails: alphatyicbnkdleoxkthes123fd56569565@gmail.com

SENSITIVE: "any aged group and alphatyic(b)nkdleoxk%t/hes123fd56569565@gmail.com and othere data missing...!"
  => Found emails: nkdleoxk%t/hes123fd56569565@gmail.com

SENSITIVE: "27 age and alphatyicbnk.?'.,dleoxkthes123fd56569565@gmail.com and othere data missing...! other@email.co"
  => Found emails: dleoxkthes123fd56569565@gmail.com other@email.co

SENSITIVE: "27 age and alphatyicbnkdleo$#-=+xkthes123fd56569565@gmail.com and othere data missing...!"
  => Found emails: alphatyicbnkdleo$#-=+xkthes123fd56569565@gmail.com

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

SENSITIVE: "user!test@example.com"
  => Found emails: user!test@example.com

SENSITIVE: "user#tag@example.com"
  => Found emails: user#tag@example.com

SENSITIVE: "user$admin@example.com"
  => Found emails: user$admin@example.com

SENSITIVE: "user%percent@example.com"
  => Found emails: user%percent@example.com

SENSITIVE: "user&name@example.com"
  => Found emails: user&name@example.com

SENSITIVE: "user'quote@example.com"
  => Found emails: user'quote@example.com

SENSITIVE: "user*star@example.com"
  => Found emails: user*star@example.com

SENSITIVE: "user=equal@example.com"
  => Found emails: user=equal@example.com

SENSITIVE: "user?question@example.com"
  => Found emails: user?question@example.com

SENSITIVE: "user^caret@example.com"
  => Found emails: user^caret@example.com

SENSITIVE: "user_underscore@example.com"
  => Found emails: user_underscore@example.com

SENSITIVE: "user`backtick@example.com"
  => Found emails: user`backtick@example.com

SENSITIVE: "userbrace@example.com"
  => Found emails: userbrace@example.com

SENSITIVE: "user|pipe@example.com"
  => Found emails: user|pipe@example.com

SENSITIVE: "user}brace@example.com"
  => Found emails: user}brace@example.com

SENSITIVE: "user~tilde@example.com"
  => Found emails: user~tilde@example.com

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

SENSITIVE: "user..double@domain.com"
  => Found emails: double@domain.com

SENSITIVE: ".user@domain.com"
  => Found emails: user@domain.com

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

SENSITIVE: ""unclosed@example.com"
  => Found emails: unclosed@example.com

SENSITIVE: ""user"name@example.com"
  => Found emails: name@example.com

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
Time: 1464 ms
Ops/sec: 87431693
Validations: 92800000

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
