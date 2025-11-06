# 🛡️ Armorly

**Universal Security Extension for AI-Powered Browsers**

Armorly is a security extension designed to protect users of AI-powered browsers (ChatGPT, Perplexity, BrowserOS, etc.) from prompt injection attacks, memory poisoning, and other AI-specific threats. It provides real-time detection and blocking of malicious content targeting AI agents.

> **Version 0.2.0** - Active blocking now enabled! NetworkInterceptor integrated, 20 blocking rules active, CSRF protection expanded.
>
> ⚠️ **Development Status**: This extension is in active development (v0.2.0). Core blocking infrastructure is now functional. See [Gap Analysis](#gap-analysis) for remaining work before v1.0.

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
- **CSRF Protection**: Blocks unauthorized cross-origin requests to ChatGPT memory API
- **Request Monitoring**: Logs suspicious network activity (detection only, limited blocking)
- **Credential Detection**: Identifies potential credential leaks in request payloads

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
| Network | Request Blocker | Blocks malicious requests | ⚠️ Limited |
| Network | CSRF Rules | Blocks memory poisoning | ✅ Active |
| Input | Form Interceptor | Sanitizes user input | ✅ Active |
| Storage | Memory Protector | Monitors localStorage | ✅ Active |

---

## 🧪 Testing

To test the extension:

```bash
# Run automated tests
node tests/run-tests.js

# Test on known attack vectors
# 1. Visit a page with hidden text
# 2. Check badge for threat count
# 3. Open popup to view detected threats
```

See `tests/TESTING-GUIDE.md` for detailed testing instructions.

---

## 📊 Gap Analysis

### ✅ Recently Fixed (v0.2.0)

#### 1. **Network Request Blocking Enabled** ✅
- **Status**: FIXED - `NetworkInterceptor` now imported and initialized in `service-worker.js`
- **Impact**: Advanced network-level blocking of data exfiltration and malicious domains is now active
- **Current State**: NetworkInterceptor monitors all requests with credential detection and payload analysis
- **Code Location**: `background/service-worker.js` lines 57-70

#### 2. **Request Blocker Active Mode Enabled** ✅
- **Status**: FIXED - `RequestBlocker` switched from permissive to active blocking mode
- **Changes**:
  - `blockDataExfiltration: true` ✅
  - `blockCSRF: true` ✅
  - `dynamicBlocking: true` ✅
- **Impact**: Now actively blocks threats instead of just logging them
- **Code Location**: `background/request-blocker.js` lines 32-43

#### 3. **Expanded Blocking Rules** ✅
- **Status**: FIXED - Expanded from 2 to 20 declarativeNetRequest rules
- **New Coverage**:
  - ChatGPT & Claude memory API protection (CSRF)
  - Perplexity API protection
  - Malicious TLDs (.tk, .ml, .ga, .cf, .gq)
  - Data exfiltration endpoints (pastebin.com/raw, transfer.sh, anonfiles.com)
  - JavaScript injection patterns (eval, javascript:, data:text/html)
  - Known malicious domains (evil.com, malware.com, phishing.com, etc.)
- **Code Location**: `rules/csrf-rules.json` (20 rules)

#### 4. **Expanded Malicious Domain List** ✅
- **Status**: IMPROVED - Expanded from 3 to 30+ malicious domains and patterns
- **Current State**: Includes malicious TLDs, C2 patterns, anonymous file hosts, and URL shorteners
- **Code Location**: `background/request-blocker.js` lines 45-77

---

### � Remaining Critical Gaps

#### 5. **Limited Threat Intelligence Scale**
- **Issue**: Only 30+ malicious domains vs millions in mature blocklists
- **Impact**: Won't block most real-world malicious domains
- **Current State**: Manually curated list of common attack patterns
- **Fix Required**: Integrate threat intelligence feeds (e.g., abuse.ch, PhishTank)
- **Estimated Effort**: 2-3 weeks to integrate and test

### �🟡 Moderate Gaps (Detection vs Prevention)

#### 6. **Content Sanitizer Not Aggressive Enough**
- **Issue**: `aggressiveMode: false` by default
- **Impact**: May miss sophisticated obfuscation techniques
- **Current State**: Conservative blocking to avoid false positives
- **Trade-off**: More aggressive = more false positives
- **Code Location**: `content/content-sanitizer.js` line 41

#### 7. **No Persistent Threat Intelligence Updates**
- **Issue**: Pattern library is static, no auto-updates
- **Impact**: Won't detect new attack patterns without extension updates
- **Current State**: Patterns hardcoded in `lib/pattern-library.js`
- **Fix Required**: Implement auto-update mechanism for patterns
- **Partial Implementation**: `ThreatIntelligence` class exists but not fully integrated

#### 8. **Limited Browser-Specific Protection**
- **Issue**: Generic implementation, not optimized for specific AI browsers
- **Impact**: Missing browser-specific attack vectors
- **Current State**: Only basic platform detection, no specialized blocking
- **Fix Required**: Implement browser-specific interceptors for Atlas, Comet, BrowserOS
- **Code Location**: `background/browseros-api-interceptor.js` exists but minimal

### 🟢 Minor Gaps (Polish & Features)

#### 9. **No User Whitelist Management**
- **Issue**: Hardcoded whitelist, users can't add trusted sites
- **Impact**: May block legitimate sites, no way to disable per-site
- **Fix Required**: Add whitelist UI in options page
- **Code Location**: `options/options.html` exists but minimal

#### 10. **No Export/Import of Threat Logs**
- **Issue**: Can't export threat data for analysis
- **Impact**: Limited forensics capability
- **Fix Required**: Add export button in popup

#### 11. **Performance Monitoring Not Exposed**
- **Issue**: Performance stats collected but not shown to user
- **Impact**: Users can't see extension overhead
- **Fix Required**: Add performance tab in popup

---

## 🆚 Comparison to uBlock Origin

| Feature | uBlock Origin | Armorly (v0.2.0) | Status |
|---------|---------------|------------------|--------|
| **Domain Blocking** | ✅ Millions of domains | ⚠️ 30+ domains/patterns | � Improved |
| **Request Blocking** | ✅ Real-time via rules | ✅ 20 declarative rules | 🟢 Active |
| **Network Interception** | ✅ Full monitoring | ✅ Full monitoring | 🟢 Active |
| **Pattern Updates** | ✅ Auto-updates | ❌ Static | 🟡 Moderate |
| **User Whitelisting** | ✅ Full UI | ❌ Hardcoded | 🟢 Minor |
| **Performance** | ✅ <5ms | ✅ <50ms | ✅ Good |
| **AI-Specific Detection** | ❌ None | ✅ 50+ patterns | ✅ Unique |
| **Prompt Injection** | ❌ None | ✅ Advanced | ✅ Unique |
| **Memory Poisoning** | ❌ None | ✅ CSRF protection | ✅ Unique |

**Verdict**: Armorly v0.2.0 now has active blocking infrastructure with unique AI-specific detection. Still needs larger threat intelligence feeds to match uBlock Origin's scale.

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
