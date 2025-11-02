# Armorly - Comprehensive Testing Guide

## 🧪 Testing All 37 Security Components

This guide provides ruthless testing procedures for all security components.

---

## 1. XSS Monitor Tests

### Test Cases:
```javascript
// Test 1: Script tag injection
<script>alert('XSS')</script>

// Test 2: Event handler injection
<img src=x onerror="alert(1)">
<body onload="alert(1)">

// Test 3: JavaScript protocol
<a href="javascript:alert(1)">Click</a>

// Test 4: Data URI with script
<iframe src="data:text/html,<script>alert(1)</script>">

// Test 5: SVG injection
<svg onload="alert(1)">

// Test 6: Encoded XSS
&#60;script&#62;alert(1)&#60;/script&#62;
%3Cscript%3Ealert(1)%3C/script%3E
```

**Expected**: All should be blocked with CRITICAL severity

---

## 2. SQL Injection Monitor Tests

### Test Cases:
```sql
-- Test 1: UNION-based injection
' UNION SELECT * FROM users--

-- Test 2: Boolean-based blind injection
' OR '1'='1
' OR 1=1--

-- Test 3: Time-based blind injection
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--

-- Test 4: Error-based injection
' AND 1=CONVERT(int, (SELECT @@version))--

-- Test 5: Stacked queries
'; DROP TABLE users--
'; DELETE FROM users WHERE 1=1--

-- Test 6: Information schema
' UNION SELECT * FROM information_schema.tables--
```

**Expected**: All should be blocked with CRITICAL severity

---

## 3. Code Injection Monitor Tests

### Test Cases:
```bash
# Test 1: Command injection
; ls -la
&& cat /etc/passwd
| whoami

# Test 2: Template injection
{{7*7}}
${7*7}
<%= 7*7 %>

# Test 3: Code execution
eval("malicious code")
exec("rm -rf /")
system("cat /etc/passwd")

# Test 4: Path traversal
../../etc/passwd
..%2F..%2Fetc%2Fpasswd
```

**Expected**: All should be blocked with CRITICAL severity

---

## 4. CORS Monitor Tests

### Test Cases:
```javascript
// Test 1: Wildcard origin
Origin: *

// Test 2: Null origin
Origin: null

// Test 3: File origin
Origin: file://

// Test 4: Credentials with wildcard
Origin: *
Headers: { Authorization: "Bearer token" }

// Test 5: Cross-origin with credentials
Origin: https://evil.com
Headers: { Cookie: "session=abc123" }
```

**Expected**: Wildcard and credential leaks should be blocked

---

## 5. CSP Monitor Tests

### Test Cases:
```javascript
// Test 1: Unsafe inline script
<script>alert(1)</script>

// Test 2: Unsafe eval
eval("alert(1)")

// Test 3: CSP bypass via JSONP
<script src="https://evil.com/jsonp?callback=alert"></script>

// Test 4: Base URI violation
<base href="https://evil.com">

// Test 5: Weak policy
Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'
```

**Expected**: All violations should be detected and logged

---

## 6. Clickjacking Monitor Tests

### Test Cases:
```html
<!-- Test 1: Sensitive domain framing -->
<iframe src="https://accounts.google.com"></iframe>

<!-- Test 2: Cross-origin framing -->
<iframe src="https://paypal.com"></iframe>

<!-- Test 3: Transparent overlay -->
<div style="opacity: 0; z-index: 9999; position: absolute;"></div>

<!-- Test 4: Missing X-Frame-Options -->
Response headers without X-Frame-Options

<!-- Test 5: Frame busting -->
if (top !== self) top.location = self.location;
```

**Expected**: Sensitive domain framing should be blocked

---

## 7. WebRTC Leak Monitor Tests

### Test Cases:
```javascript
// Test 1: Unknown STUN server
{
  iceServers: [
    { urls: 'stun:evil.com:3478' }
  ]
}

// Test 2: Private IP leak
ICE candidate: 192.168.1.100

// Test 3: Localhost leak
ICE candidate: 127.0.0.1

// Test 4: Unknown TURN server
{
  iceServers: [
    { urls: 'turn:evil.com:3478' }
  ]
}
```

**Expected**: Private IP leaks should be detected

---

## 8. DNS Rebinding Monitor Tests

### Test Cases:
```javascript
// Test 1: Public to private IP change
example.com: 1.2.3.4 -> 192.168.1.1

// Test 2: Localhost access
example.com -> 127.0.0.1

// Test 3: Private IP access
example.com -> 10.0.0.1

// Test 4: Link-local access
example.com -> 169.254.1.1
```

**Expected**: DNS rebinding attacks should be blocked

---

## 9. Phishing Monitor Tests

### Test Cases:
```
Test 1: Homograph attack
https://gооgle.com (Cyrillic 'o')
https://аpple.com (Cyrillic 'a')

Test 2: Suspicious TLD
https://paypal-login.tk
https://amazon-verify.ml

Test 3: Domain spoofing
https://paypa1.com (1 instead of l)
https://g00gle.com (0 instead of o)

Test 4: Subdomain spoofing
https://login.paypal.evil.com
```

**Expected**: All phishing attempts should be detected

---

## 10. Cryptojacking Monitor Tests

### Test Cases:
```javascript
// Test 1: Known mining script
https://coinhive.com/lib/coinhive.min.js

// Test 2: Known mining domain
https://crypto-loot.com/miner.js

// Test 3: Mining keywords in script
var miner = new CoinHive.Anonymous('key');

// Test 4: WebAssembly mining
WebAssembly.instantiate(cryptonightModule);

// Test 5: High CPU usage
CPU usage > 80% for extended period
```

**Expected**: All mining attempts should be blocked

---

## 🚀 Running Tests

### Automated Tests:
```bash
# Run all tests
node tests/run-tests.js

# Run specific test file
node tests/security-components.test.js
```

### Manual Testing:
1. Load extension in Chrome (chrome://extensions/)
2. Open DevTools Console
3. Navigate to test pages
4. Inject test payloads
5. Verify threats are detected and logged
6. Check statistics in console

### Expected Console Output:
```
[Armorly] All 37 security components initialized successfully
[Armorly] Threat detected: XSS_ATTACK CRITICAL
[Armorly] Threat detected: SQL_INJECTION CRITICAL
[Armorly] Threat detected: COMMAND_INJECTION CRITICAL
```

---

## 📊 Success Criteria

### All Tests Must:
- ✅ Detect all attack vectors
- ✅ Block CRITICAL threats
- ✅ Log threats silently (no user popups)
- ✅ Maintain performance (< 50ms per check)
- ✅ Handle edge cases gracefully
- ✅ Not produce false positives on legitimate content

### Performance Benchmarks:
- XSS check: < 10ms
- SQL injection check: < 10ms
- Code injection check: < 10ms
- CORS check: < 5ms
- CSP check: < 5ms
- Phishing check: < 20ms
- Cryptojacking check: < 15ms

---

## 🔍 Debugging

### Enable Verbose Logging:
```javascript
// In service-worker.js
console.log('[Armorly] Component statistics:', monitor.getStatistics());
```

### Check Component Status:
```javascript
// Get statistics for each component
sessionMonitor.getStatistics()
xssMonitor.getStatistics()
sqlInjectionMonitor.getStatistics()
// ... etc
```

---

## ✅ Test Checklist

- [ ] XSS Monitor: 6 test cases
- [ ] SQL Injection Monitor: 6 test cases
- [ ] Code Injection Monitor: 4 test cases
- [ ] CORS Monitor: 5 test cases
- [ ] CSP Monitor: 5 test cases
- [ ] Clickjacking Monitor: 5 test cases
- [ ] WebRTC Leak Monitor: 4 test cases
- [ ] DNS Rebinding Monitor: 4 test cases
- [ ] Phishing Monitor: 4 test cases
- [ ] Cryptojacking Monitor: 5 test cases
- [ ] Memory Leak Monitor: 3 test cases
- [ ] Resource Exhaustion Monitor: 4 test cases
- [ ] All other 25 components: Basic functionality

**Total: 60+ test cases across 37 components**

---

## 🎯 Final Validation

After all tests pass:
1. ✅ Build extension: `./build.sh`
2. ✅ Load in Chrome
3. ✅ Test on real websites
4. ✅ Monitor console for errors
5. ✅ Verify silent operation (no popups)
6. ✅ Check performance impact
7. ✅ Validate all 37 components initialized

**Armorly is production-ready when all tests pass! 🛡️**

