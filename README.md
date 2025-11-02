# 🛡️ Armorly

**Universal Security for Agentic Browsers**

Armorly is the world's first universal security extension for AI-powered browsers. It protects users across **all agentic browsers**—ChatGPT Atlas, Perplexity Comet, BrowserOS, Brave Leo, Arc, and standard Chrome—from prompt injection, memory poisoning, data exfiltration, and cross-domain attacks.

**🌍 Universal Protection**: Works across all browsers with adaptive, browser-specific security features
**🔒 Always Enabled**: All protections active by default—no configuration needed
**🎯 Agentic-First**: Built specifically to secure AI agents operating with full user privileges

---

## Features

### Universal Protection (All Browsers)
- **🔍 Universal Prompt Injection Detection**: 50+ patterns detecting hidden malicious instructions
- **👁️ Hidden Content Analysis**: Detects white-on-white text, zero-opacity, off-screen positioning
- **📝 HTML Comment Scanning**: Finds prompt injections in comments (Perplexity Comet attack vector)
- **📋 Form Field Validation**: Scans hidden inputs and textareas for malicious instructions
- **🔤 Obfuscation Detection**: Identifies zero-width characters and encoding tricks
- **🌐 Network Monitoring**: Tracks suspicious requests and data exfiltration attempts
- **💾 Storage Protection**: Monitors localStorage/sessionStorage for memory poisoning
- **🎭 Semantic Analysis**: Detects instruction-like language patterns

### Browser-Specific Protection
- **BrowserOS**: API interception, accessibility tree sanitization
- **ChatGPT Atlas**: OWL architecture monitoring (planned)
- **Perplexity Comet**: Enhanced hidden content detection
- **Brave Leo**: In-browser AI assistant protection (planned)

### User Experience
- **Silent Operation**: No popups or interruptions—just protection
- **Smart Badge**: Shows threat count per page with color coding
- **Detailed Dashboard**: Click badge to view all detected threats
- **Performance Optimized**: < 50ms overhead with intelligent caching
- **Privacy-First**: All analysis happens locally on your device

---

## Installation

1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the armorly directory
5. The extension will start protecting you immediately

---

## How It Works

Armorly operates silently in the background:

1. **Request Monitoring**: Intercepts requests to AI service endpoints
2. **DOM Scanning**: Analyzes page content for hidden threats
3. **Pattern Matching**: Compares against 47+ known attack patterns
4. **Threat Scoring**: Assigns risk scores based on multiple factors
5. **Silent Blocking**: Blocks threats and updates badge counter
---

## Usage

Once installed, Armorly works silently:

- Badge shows threat count (e.g., "3" = 3 threats blocked)
- Badge color: green (safe), yellow (1-5 threats), red (6+ threats)
- Click badge to view blocked threats
- No popups or interruptions

---

## Technical Details

### Architecture
- **Manifest V3** Chrome extension
- **Service Worker** for background processing
- **Content Scripts** for DOM analysis
- **Performance**: < 50ms overhead with LRU caching

### Protection Mechanisms
- **CSRF Detection**: Monitors requests to AI service endpoints
- **DOM Scanning**: Analyzes page content for hidden threats
- **Pattern Matching**: 47+ attack signatures
- **AI Agent Detection**: Heightened protection when agents active

### Files
- `background/service-worker.js` - Main coordinator
- `content/content-script.js` - Page orchestrator
- `content/dom-scanner.js` - Threat detection
- `lib/pattern-library.js` - Attack patterns
- `lib/csrf-detector.js` - Memory protection
- `lib/ai-agent-detector.js` - Agent detection

---

## License

MIT License - See LICENSE file for details
