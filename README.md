# 🛡️ Armorly

**Universal Security Extension for AI-Powered Browsers**

Armorly is a security extension designed to protect users of AI-powered browsers (ChatGPT, Perplexity, BrowserOS, etc.) from prompt injection attacks, memory poisoning, and other AI-specific threats. It provides real-time detection and limited blocking of malicious content targeting AI agents.

> **Version 1.0.0** - Security fixes applied! XSS vulnerabilities patched, fake domains removed, permissions documented.
>
> ⚠️ **IMPORTANT - PROOF OF CONCEPT STATUS**
>
> This extension demonstrates AI-specific security techniques but has significant limitations:
> - **Network blocking is DETECTION ONLY** due to Chrome Manifest V3 restrictions
> - **Threat intelligence is limited** (~15 rules vs. millions needed for real protection)
> - **No auto-updates** for threat patterns
> - **Not ready for production** without integration of real threat feeds
>
> See [Limitations](#limitations) below for full details.

---

## 🎯 Core Features

### ✅ Currently Working

#### Content Protection
- **DOM Scanning**: Real-time analysis of page content for prompt injection patterns
- **Pattern Matching**: 50+ regex patterns detecting instruction hijacking, goal manipulation, and context confusion
- **Hidden Content Detection**: Identifies white-on-white text, zero-opacity elements, and off-screen positioning
- **HTML Comment Scanning**: Detects malicious instructions in HTML comments
- **Mutation Monitoring**: Watches for dynamically injected malicious content
- **Form Interception**: Monitors and sanitizes form inputs before submission

#### Network Protection
- **CSRF Protection**: Blocks unauthorized cross-origin requests to ChatGPT/Claude/Perplexity APIs (15 declarativeNetRequest rules)
- **Request Monitoring**: **DETECTION ONLY** - Chrome Manifest V3 does not allow webRequest API to block
- **Credential Detection**: Identifies potential credential leaks in request payloads (detection, no blocking)
- **Note**: NetworkInterceptor can detect threats but cannot prevent them. Only declarativeNetRequest rules can block.

#### AI Agent Detection
- **Platform Detection**: Identifies ChatGPT, Perplexity, BrowserOS, and other AI platforms
- **Threat Multiplier**: Increases protection sensitivity when AI agents are active
- **Context-Aware Scoring**: Adjusts threat scores based on AI agent presence

#### User Interface
- **Badge Counter**: Shows number of threats detected on current page
- **Popup Dashboard**: Displays threat log, statistics, and protection status
- **Performance Monitoring**: Tracks extension overhead (typically <50ms)

---

## 📦 Installation

### For Development/Testing

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/armorly.git
   cd armorly
   ```

2. Build the extension:
   ```bash
   ./build.sh
   ```

3. Load in Chrome:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `build` folder

4. The extension will start protecting immediately

---

## 🔍 How It Works

### Detection Pipeline

1. **Content Scripts** inject into every page at `document_start`
2. **DOM Scanner** analyzes all text nodes, attributes, and comments
3. **Pattern Library** matches against 50+ known attack patterns
4. **Threat Detector** scores and aggregates threats
5. **Content Sanitizer** removes or neutralizes malicious content
6. **Service Worker** coordinates protection and logs threats

### Protection Layers

| Layer | Component | Function | Status |
|-------|-----------|----------|--------|
| DOM | Content Sanitizer | Removes malicious elements | ✅ Active |
| DOM | Mutation Blocker | Monitors dynamic changes | ✅ Active |
| Network | NetworkInterceptor | **Detection only** (MV3 limitation) | ⚠️ Detection |
| Network | CSRF Rules (declarativeNetRequest) | Blocks CSRF attacks | ✅ Active (15 rules) |
| Input | Form Interceptor | Sanitizes user input | ✅ Active |
| Storage | Memory Protector | Monitors localStorage | ✅ Active |

---

## 🧪 Testing

```bash
# Install dependencies
npm install

# Run automated tests
npm test

# Run security audit
npm run audit:security

# Validate manifest.json
npm run validate:manifest

# Build extension
npm run build

# Build and verify
npm run dev
```

See `tests/TESTING-GUIDE.md` for detailed testing instructions.

---

## ⚠️ Limitations

### Chrome Manifest V3 Restrictions

**Network Blocking is Detection-Only**: Chrome Manifest V3 removed the ability to block network requests via `webRequest` API. This means:
- ❌ Cannot dynamically block malicious requests based on payload analysis
- ❌ Cannot prevent data exfiltration in real-time
- ❌ Cannot block credential leaks detected in request bodies
- ✅ CAN block via static `declarativeNetRequest` rules (but only 15 active)
- ✅ CAN detect and log all threats for user awareness

**Implications**: The extension can WARN you about threats but cannot prevent all of them. Real blocking requires adding domains to `declarativeNetRequest` rules beforehand.

### Limited Threat Intelligence

Current coverage: **~15 blocking rules**
Required for production: **10,000+ rules**

The extension includes only demonstration-level threat data:
- ❌ Fake domains (evil.com, malware.com) have been **removed**
- ✅ Real patterns included: malicious TLDs (.tk, .ml, etc.), data exfiltration services
- ❌ No integration with live threat feeds (abuse.ch, PhishTank, etc.)
- ❌ No auto-updates for threat patterns
- ❌ Static patterns cannot detect zero-day attacks

**To make production-ready**: Must integrate threat intelligence feeds and implement auto-update mechanism.

### Security Vulnerabilities Fixed (v1.0.0)

- ✅ **XSS in popup.js** - Fixed by using safe DOM methods instead of innerHTML
- ✅ **XSS in action-authorizer.js** - Fixed by using createElement/textContent
- ✅ **HTML injection in pattern-library.js** - Fixed by using DOMParser
- ✅ **Service worker browser API usage** - Added defensive error handling
- ✅ **Over-privileged permissions** - Removed unused "scripting" permission

See [CHANGELOG.md](CHANGELOG.md) for full security fix details.

---

## 📊 What Was Actually Fixed (v1.0.0)

### ✅ Critical Security Fixes

#### 1. **NetworkInterceptor - Clarified MV3 Limitations** ✅
- **Status**: DOCUMENTED - NetworkInterceptor is detection-only, cannot block in MV3
- **Changes**: Removed misleading `return { cancel: true }` statements, added clear documentation
- **Impact**: Users now understand extension detects but cannot always block threats
- **Code Location**: `background/network-interceptor.js`

#### 2. **XSS Vulnerabilities Patched** ✅
- **Status**: FIXED - All innerHTML usage with user data replaced with safe DOM methods
- **Files Fixed**:
  - `popup/popup.js` - Safe DOM manipulation for threat display
  - `content/action-authorizer.js` - Safe dialog creation
  - `lib/pattern-library.js` - DOMParser instead of innerHTML
- **Impact**: Extension no longer vulnerable to XSS attacks via malicious threat data

#### 3. **Fake Malicious Domains Removed** ✅
- **Status**: FIXED - Placeholder domains (evil.com, malware.com, etc.) removed
- **Changes**: Reduced from 20 to 15 rules, removed 5 fake domain rules
- **Documentation**: Added clear disclaimers about proof-of-concept status
- **Code Location**: `rules/csrf-rules.json`, `background/request-blocker.js`

#### 4. **Permissions Documented** ✅
- **Status**: FIXED - All permissions justified, unused "scripting" removed
- **Documentation**: Created `PERMISSIONS.md` with Chrome Web Store justifications
- **Code Location**: `manifest.json`

#### 5. **Development Infrastructure Added** ✅
- **Status**: ADDED - Complete package.json with test framework and scripts
- **Features**:
  - npm scripts for testing, linting, building
  - Manifest validator
  - Security audit tool
  - ESLint configuration
- **Code Location**: `package.json`, `scripts/`, `tests/`

---

## 🚧 Remaining Gaps for Production

### 🔴 Critical Gaps

#### Limited Threat Intelligence
- **Issue**: Only 15 blocking rules vs. millions in mature blocklists
- **Impact**: Won't block most real-world malicious domains
- **Fix Required**: Integrate threat intelligence feeds (abuse.ch, PhishTank, URLhaus)
- **Estimated Effort**: 3-4 weeks

#### No Auto-Updates for Threat Patterns
- **Issue**: Pattern library is static, cannot update without releasing new version
- **Impact**: Won't detect new attack patterns without manual updates
- **Fix Required**: Implement dynamic rule updates via declarativeNetRequest API
- **Estimated Effort**: 2-3 weeks

### 🟡 Moderate Gaps

#### Limited Test Coverage
- **Issue**: Only 2 test files for 28,334 lines of code (~5% coverage)
- **Impact**: High risk of bugs and regressions
- **Fix Required**: Achieve 70% test coverage minimum
- **Estimated Effort**: 4-6 weeks

#### No ML-Based Detection
- **Issue**: Only regex pattern matching, no anomaly detection
- **Impact**: Cannot detect sophisticated zero-day attacks
- **Fix Required**: Implement machine learning models
- **Estimated Effort**: 8-12 weeks

---

## 🆚 Comparison to uBlock Origin

| Feature | uBlock Origin | Armorly (v1.0.0) | Notes |
|---------|---------------|------------------|-------|
| **Domain Blocking** | ✅ Millions of domains | ⚠️ 15 rules | Need threat feeds |
| **Request Blocking** | ✅ Dynamic blocking | ⚠️ Static rules only | MV3 limitation |
| **Network Monitoring** | ✅ Full control | ⚠️ Detection only | MV3 limitation |
| **Pattern Updates** | ✅ Auto-updates | ❌ Static | Need to implement |
| **User Whitelisting** | ✅ Full UI | ❌ Hardcoded | Need UI |
| **Performance** | ✅ <5ms | ✅ <50ms | Good |
| **AI-Specific Detection** | ❌ None | ✅ 50+ patterns | **Unique** |
| **Prompt Injection** | ❌ None | ✅ Advanced | **Unique** |
| **Memory Poisoning** | ❌ None | ✅ CSRF protection | **Unique** |
| **XSS Protection** | ❌ None | ✅ Fixed in v1.0.0 | **Secure** |

**Verdict**: Armorly v1.0.0 provides unique AI-specific protections that uBlock Origin doesn't have, but lacks the scale and maturity for general web security. Best used **alongside** uBlock Origin, not as a replacement.

---

## 🛣️ Roadmap to Production

### ✅ Phase 1: Core Blocking Infrastructure (v0.2.0 - COMPLETE)
- [x] Enable and integrate `NetworkInterceptor` in service worker
- [x] Switch `RequestBlocker` from permissive to active mode
- [x] Expand declarativeNetRequest rules for common attack patterns (2 → 20 rules)
- [x] Expand malicious domain list (3 → 30+ domains/patterns)

### Phase 2: Scale Threat Intelligence (Required for v1.0)
- [ ] Integrate threat intelligence feeds (abuse.ch, PhishTank, URLhaus)
- [ ] Expand to 10,000+ malicious domains
- [ ] Add auto-update mechanism for threat patterns
- [ ] Implement community threat reporting
- [ ] Add comprehensive test suite for blocking functionality
- **Estimated Timeline**: 3-4 weeks

### Phase 3: Enhanced Detection (Required for v1.0)
- [ ] Enable aggressive mode with smart whitelisting
- [ ] Add browser-specific attack detection (Atlas, Comet, BrowserOS)
- [ ] Improve obfuscation detection (base64, unicode, homoglyphs)
- [ ] Implement ML-based anomaly detection
- **Estimated Timeline**: 4-6 weeks

### Phase 4: User Experience (Nice to have for v1.0)
- [ ] Build whitelist management UI
- [ ] Add threat log export/import
- [ ] Implement per-site protection toggle
- [ ] Add detailed threat explanations in popup
- [ ] Create onboarding tutorial
- [ ] Expose performance monitoring in UI
- **Estimated Timeline**: 2-3 weeks

### Phase 5: Advanced Features (Post v1.0)
- [ ] Machine learning-based detection
- [ ] Community threat sharing network
- [ ] Enterprise policy management
- [ ] Browser-specific API interception (BrowserOS, Atlas)
- [ ] Integration with SIEM systems
- **Estimated Timeline**: 8-12 weeks

---

## 🏗️ Architecture

### Core Components

```
armorly/
├── manifest.json                 # Extension configuration
├── background/
│   ├── service-worker.js        # Main coordinator (✅ Active)
│   ├── request-blocker.js       # Network blocking (⚠️ Permissive mode)
│   ├── network-interceptor.js   # Advanced blocking (❌ Not used)
│   ├── ai-agent-detector.js     # Platform detection (✅ Active)
│   ├── threat-detector.js       # Threat scoring (✅ Active)
│   └── [25+ other monitors]     # Various protection modules
├── content/
│   ├── content-script.js        # Page coordinator (✅ Active)
│   ├── content-sanitizer.js     # DOM cleaning (✅ Active)
│   ├── mutation-blocker.js      # Dynamic protection (✅ Active)
│   ├── dom-scanner.js           # Threat detection (✅ Active)
│   ├── form-interceptor.js      # Input sanitization (✅ Active)
│   └── [10+ other protectors]   # Various content modules
├── lib/
│   ├── pattern-library.js       # Attack patterns (✅ Active)
│   ├── csrf-detector.js         # Memory protection (✅ Active)
│   └── [10+ other libraries]    # Shared utilities
├── rules/
│   └── csrf-rules.json          # Declarative blocking rules (✅ Active)
└── popup/
    ├── popup.html               # User interface (✅ Active)
    └── popup.js                 # Dashboard logic (✅ Active)
```

---

## 🤝 Contributing

This project is in active development. Contributions are welcome, especially for:
- Expanding the malicious domain list
- Adding new prompt injection patterns
- Improving browser-specific detection
- Writing tests for edge cases

---

## 📄 License

MIT License - See LICENSE file for details

---

## ⚠️ Disclaimer

This extension is provided as-is for research and educational purposes. While it provides meaningful protection against AI-specific attacks, it is not a complete security solution and should be used alongside other security tools. The developers make no guarantees about the effectiveness of this extension against all attack vectors.
