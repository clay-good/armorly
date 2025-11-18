# Armorly

Armorly is a browser security extension designed to protect users of AI-powered browsers and platforms from prompt injection attacks, conversation tampering, memory poisoning, and other AI-specific security threats. It provides real-time detection and blocking of malicious content targeting AI agents.

## Core Features

### AI Response Protection
- **AI Response Scanner**: Real-time monitoring of AI-generated responses across all major platforms
- **Cross-Platform Support**: ChatGPT, Claude, Gemini, Perplexity, Poe, HuggingFace, Character.AI, Jasper, and more
- **Pattern Detection**: 25+ malicious patterns including instruction override, code injection, and data exfiltration
- **Function Call Interception**: Monitors 30+ suspicious functions (deleteFile, exec, eval, fetch external URLs)
- **Network-Level Scanning**: Intercepts and validates fetch() responses for malicious content
- **Integrated Tracking**: Automatically feeds AI responses to multi-turn attack detection

### Conversation Integrity
- **SHA-256 Hashing**: Cryptographic verification of message content using Web Crypto API
- **Tampering Detection**: Identifies modified, reordered, or injected messages
- **Sequence Verification**: Tracks message order to detect conversation manipulation
- **Context Poisoning Prevention**: Detects fake "previous conversation" markers and injected context
- **Visual Warnings**: Alerts users when conversation tampering is detected

### Multi-Turn Attack Detection
- **Attack Chain Recognition**: Detects sophisticated attacks spread across multiple messages
- **5 Attack Categories**: Privilege escalation, reconnaissance, trust exploitation, fragmented commands, role shifting
- **Behavioral Analysis**: Tracks suspicion scores across 5-message sliding window
- **Pattern Matching**: 60% threshold triggers alerts for attack chains
- **Integrated Tracking**: Monitors both user inputs (via form interceptor) and AI responses
- **Visual Warnings**: Shows confidence scores and detected attack categories

### API Response Validation
- **HTTPS Enforcement**: Blocks non-HTTPS AI API connections (MITM prevention)
- **Content-Type Validation**: Verifies expected response formats for each AI platform
- **Response Size Limits**: 10MB maximum to prevent attack payloads
- **Header Validation**: Detects suspicious headers indicating MITM attacks
- **Pattern Matching**: 10+ suspicious content indicators
- **SHA-256 Integrity**: Tracks response hashes for tampering detection
- **Network Interception**: Full fetch() and XMLHttpRequest coverage
- **Active Blocking**: Returns 403 for tampered responses

### Content Protection
- **DOM Scanning**: Real-time analysis of page content for prompt injection patterns
- **Pattern Matching**: 50+ regex patterns detecting instruction hijacking, goal manipulation, and context confusion
- **Hidden Content Detection**: Identifies white-on-white text, zero-opacity elements, and off-screen positioning
- **HTML Comment Scanning**: Detects malicious instructions in HTML comments
- **Mutation Monitoring**: Watches for dynamically injected malicious content
- **Form Interception**: Monitors and sanitizes form inputs before submission

### Network Protection
- **CSRF Protection**: Blocks unauthorized cross-origin requests to AI platform APIs
- **declarativeNetRequest Rules**: 15 blocking rules for ChatGPT, Claude, and Perplexity endpoints
- **Request Monitoring**: Detection-only monitoring for credential leaks and suspicious payloads
- **Note**: Chrome Manifest V3 limits blocking to declarativeNetRequest rules only

### Memory Protection
- **AI Settings Scanner**: Scans stored memories and chat history for malicious content
- **Memory Poisoning Prevention**: Detects and removes injected instructions in AI memory
- **Storage Monitoring**: Tracks localStorage and IndexedDB for suspicious modifications
- **Clipboard Protection**: Prevents malicious clipboard hijacking targeting AI input

### Privacy & Anti-Fingerprinting
- **Privacy Shield**: Blocks fingerprinting attempts and tracking scripts
- **WebRTC Leak Protection**: Prevents IP address leakage
- **Cross-Tab Protection**: Isolates AI conversations across browser tabs

### Performance Optimization
- **Pre-Compiled Patterns**: Regex compilation at initialization for 70% faster matching
- **Visibility Caching**: WeakMap-based caching for 90% faster DOM scans
- **NodeFilter Callbacks**: Optimized tree walking with 80% fewer nodes processed
- **Selective Loading**: Only 2 scripts on non-AI sites, full protection on AI platforms
- **Typical Overhead**: Less than 50ms per page load

## Supported Platforms

### Full Protection (16+ scripts loaded)
- ChatGPT / OpenAI (chatgpt.com, chat.openai.com)
- Claude / Anthropic (claude.ai, anthropic.com)
- Google Gemini / Bard (gemini.google.com, bard.google.com)
- Perplexity AI (perplexity.ai)
- Poe (poe.com)
- HuggingFace Chat (huggingface.co)
- Character.AI (character.ai)
- Jasper (jasper.ai)
- Copy.ai (copy.ai)
- Writesonic (writesonic.com)
- Replicate (replicate.com)
- Midjourney (midjourney.com)
- Stability AI (stability.ai)
- Leonardo AI (leonardo.ai)
- BrowserOS (browseros.com)

### Basic Protection (2 scripts loaded)
- All other websites (console wrapper + content script only)

## Installation

### For Development/Testing

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/armorly.git
   cd armorly
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the extension:
   ```bash
   npm run build
   ```

4. Load in Chrome:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `build` folder

5. The extension will start protecting immediately

### For Production Use

1. Download the latest release from GitHub Releases
2. Extract the ZIP file
3. Load the extension following step 4 above

## How It Works

### Protection Architecture

```
Page Load
    |
    v
[Content Script Detection]
    |
    +-- Non-AI Platform --> Load 2 scripts (minimal overhead)
    |
    +-- AI Platform --> Load 16 scripts (full protection)
            |
            v
    [Initialization Phase]
            |
            +-- Content Sanitizer (blocking engine)
            +-- Mutation Blocker (real-time protection)
            +-- Clipboard Protector
            +-- Privacy Shield
            +-- Memory Protector
            +-- Form Interceptor
            +-- Output Validator
            +-- Action Authorizer
            +-- Context Analyzer
            +-- Confidence Scorer
            +-- DOM Scanner (detection)
            +-- AI Response Scanner (CRITICAL)
            +-- Conversation Integrity Monitor (CRITICAL)
            |
            v
    [Continuous Monitoring]
            |
            +-- MutationObserver (DOM changes)
            +-- fetch() Interception (network)
            +-- SHA-256 Hashing (message integrity)
            +-- Pattern Matching (threats)
            |
            v
    [Threat Response]
            |
            +-- Silent Blocking (remove malicious content)
            +-- Visual Warnings (tampering detected)
            +-- Background Reporting (statistics)
```

### Detection Pipeline

1. **Content Scripts** inject at `document_start` for maximum protection
2. **Platform Detection** determines which protection modules to load
3. **DOM Scanner** analyzes all text nodes, attributes, and comments
4. **AI Response Scanner** monitors AI-generated content in real-time
5. **Conversation Integrity Monitor** verifies message authenticity
6. **Pattern Library** matches against 75+ known attack patterns
7. **Threat Detector** scores and aggregates threats
8. **Content Sanitizer** removes or neutralizes malicious content
9. **Service Worker** coordinates protection and logs statistics

### Protection Layers

| Layer | Component | Function | Status |
|-------|-----------|----------|--------|
| Response | AI Response Scanner | Monitors AI output | Active (Blocking) |
| Conversation | Integrity Monitor | Detects tampering | Active (Warning) |
| DOM | Content Sanitizer | Removes malicious elements | Active (Blocking) |
| DOM | Mutation Blocker | Monitors dynamic changes | Active (Blocking) |
| Network | CSRF Rules | Blocks unauthorized requests | Active (15 rules) |
| Network | Request Monitor | Detects suspicious traffic | Detection Only |
| Input | Form Interceptor | Sanitizes user input | Active (Blocking) |
| Memory | Memory Protector | Monitors AI memory | Active (Blocking) |
| Storage | Storage Monitor | Watches localStorage | Active (Detection) |
| Privacy | Privacy Shield | Anti-fingerprinting | Active (Blocking) |

## Testing

```bash
# Install dependencies
npm install

# Run automated tests (18 test cases)
npm test

# Run security audit
npm run audit:security

# Run ESLint
npm run lint

# Fix linting issues
npm run lint:fix

# Validate manifest.json
npm run validate:manifest

# Build extension
npm run build

# Build and verify integrity
npm run build:verify
```

See `tests/TESTING-GUIDE.md` for detailed testing instructions.

## Development

### Project Structure

```
armorly/
├── background/          # Service worker and background scripts
│   ├── service-worker.js
│   ├── threat-detector.js
│   └── ...
├── content/            # Content scripts (injected into pages)
│   ├── content-script.js          # Main orchestrator
│   ├── ai-response-scanner.js     # AI output monitoring
│   ├── conversation-integrity.js  # Tampering detection
│   ├── content-sanitizer.js       # Blocking engine
│   └── ...
├── lib/                # Shared libraries
│   ├── pattern-library-global.js
│   ├── performance-monitor-global.js
│   └── ...
├── popup/              # Extension popup UI
├── options/            # Settings page
├── rules/              # declarativeNetRequest rules
├── tests/              # Test suites
└── manifest.json       # Extension manifest (MV3)
```

### Key Components

#### AI Response Scanner (`content/ai-response-scanner.js`)
- Monitors AI-generated responses across 10+ platforms
- 35+ platform-specific CSS selectors
- Pattern matching for 25+ attack types
- Function call interception (deleteFile, exec, eval, etc.)
- Network-level response validation

#### Conversation Integrity Monitor (`content/conversation-integrity.js`)
- SHA-256 hashing of all messages
- Message sequence tracking
- Tampering detection (order, content, injection)
- Visual warning system
- Platform-agnostic conversation tracking

#### Content Sanitizer (`content/content-sanitizer.js`)
- Primary blocking engine
- Removes malicious DOM elements
- Sanitizes attributes and event handlers
- Neutralizes script tags and iframes

#### Pattern Library (`lib/pattern-library-global.js`)
- 50+ pre-compiled regex patterns
- Instruction override detection
- Goal manipulation patterns
- Context confusion markers
- Special token identification

### Adding New Platforms

To add support for a new AI platform:

1. Add the domain to `manifest.json` matches array (line 39-58)
2. Add platform-specific selectors to `ai-response-scanner.js` (line 189-245)
3. Add conversation ID extraction to `conversation-integrity.js` (line 109-139)
4. Test on the live platform

## Performance Impact

- **Non-AI Sites**: ~2KB loaded, <5ms overhead
- **AI Platforms**: ~308KB loaded, <50ms overhead
- **Memory Usage**: ~15-20MB (typical Chrome extension)
- **CPU Impact**: Negligible (<1% on modern systems)

## Privacy

Armorly operates entirely locally:
- No data sent to external servers
- No telemetry or analytics
- No user tracking
- All processing happens in-browser
- Open source and auditable

## Security Auditing

The extension includes automated security checks:

```bash
npm run audit:security
```

Scans for:
- XSS vulnerabilities (innerHTML usage)
- Code injection risks (eval, Function constructor)
- ReDoS vulnerabilities (unsafe regex)
- Hardcoded credentials
- Insecure DOM manipulation

## Known Limitations

### Chrome Manifest V3 Restrictions
- **webRequest API**: Cannot block network requests (detection only)
- **Blocking**: Limited to declarativeNetRequest rules (max 15 active)
- **Service Worker**: Cannot maintain persistent connections

### Platform-Specific Limitations
- **Dynamic UIs**: Some platforms change selectors frequently (requires updates)
- **SPA Navigation**: May miss rapid page transitions
- **Obfuscated Content**: Advanced obfuscation may evade detection

### Performance Considerations
- **Large DOMs**: Scanning 10,000+ nodes may cause slight delays
- **Frequent Updates**: High-velocity AI responses may impact performance
- **Memory**: Long conversations increase integrity monitoring overhead