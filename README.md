# Armorly

**Universal Security Extension for AI-Powered Browsers**

Armorly is a security extension designed to protect users of AI-powered browsers (ChatGPT, Perplexity, BrowserOS, etc.) from prompt injection attacks, memory poisoning, and other AI-specific threats. It provides real-time detection and limited blocking of malicious content targeting AI agents.

## Core Features

### Currently Working

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

## Installation

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

## How It Works

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
| DOM | Content Sanitizer | Removes malicious elements | Active |
| DOM | Mutation Blocker | Monitors dynamic changes | Active |
| Network | NetworkInterceptor | **Detection only** (MV3 limitation) | Detection |
| Network | CSRF Rules (declarativeNetRequest) | Blocks CSRF attacks | Active (15 rules) |
| Input | Form Interceptor | Sanitizes user input | Active |
| Storage | Memory Protector | Monitors localStorage | Active |

---

## Testing

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

```

## Disclaimer

This extension is provided as-is for research and educational purposes. While it provides meaningful protection against AI-specific attacks, it is not a complete security solution and should be used alongside other security tools. The developers make no guarantees about the effectiveness of this extension against all attack vectors.
