# Armorly

Block intrusive ads in AI chatbots. Stops sponsored content from ChatGPT, Grok, Perplexity, and all AI ad networks.

## Usage

Install. Done.

To disable: Click the puzzle icon in Chrome toolbar, find Armorly, toggle off. That's it.

There is no popup. There are no settings. There is nothing to configure. Chrome's built-in extension toggle is your on/off switch.

## Why Ads Will Destroy AI

Advertising is incompatible with AI's value proposition. Here's why:

AI's entire purpose is to give you the best answer. Ads require giving you a paid answer. These goals are mutually exclusive. When an AI recommends a specific product because the company paid for placement rather than because it's actually the best option for your trip, the AI has stopped being useful. It's now a salesperson pretending to be an advisor.

Traditional search survived ads because users understood the transaction: free results in exchange for attention. AI is different. Users ask AI questions expecting genuine expertise. They trust the response. Injecting paid content into that trust relationship isn't advertising - it's deception. The moment users realize AI recommendations are for sale, the entire value of AI-as-advisor collapses.

The ad-supported model also creates perverse incentives. An AI optimized for engagement (to show more ads) will give you answers that keep you asking questions, not answers that solve your problem. It will recommend products with high affiliate commissions, not products that fit your needs. It will become a worse AI to become a better ad platform.

OpenAI, Google, and others are walking into this trap anyway because ads are easy money. Armorly exists because some of us still want AI that works for us, not for advertisers.

## What It Does

Armorly blocks AI-native advertising - ads embedded directly into AI chatbot responses. Unlike traditional web ads served from separate domains, AI ads are injected into the LLM response itself, making them invisible to traditional ad blockers like uBlock Origin or Brave Shields.

### Ad Networks Blocked

- Koah - Serving ads in Luzia, Liner, DeepAI
- Monetzly - "Google Ads for AI conversations"
- Sponsored.so - Native AI ad platform
- Grok/X - Promoted suggestions in Grok
- Imprezia - AI ad SDK
- Google AdSense - AdSense expanding to chatbots
- ChatGPT Ads - Prepared for upcoming rollout
- Perplexity Ads - Sponsored follow-up questions

### How It Blocks

- **SDK Interception**: Blocks ad SDK global objects (Koah, Monetzly, etc.) making them unusable
- **DOM Removal**: Removes sponsored labels and ad containers using specific selectors
- **Affiliate Link Cleaning**: Strips tracking parameters (utm_*, ref, affiliate, etc.)

Note: Armorly focuses on client-side ad blocking that traditional blockers can't handle. For network-level blocking, use uBlock Origin or Brave alongside Armorly.

### Security: Hidden Prompt Injection Protection

Armorly blocks hidden prompt injection - a real AI security threat.

Malicious websites can hide instructions in invisible text. When you paste content from these pages into an AI, the hidden instructions get included and can manipulate the AI's behavior.

Armorly detects hidden elements using:
- White text on white background
- Font-size: 0 content

Content is only removed if it contains known prompt injection patterns like "ignore previous instructions", "jailbreak", "DAN mode", etc. This conservative approach prevents false positives while catching actual attacks.

## Limitations

**This extension cannot do everything. Here's what it cannot do:**

1. **Mobile apps are completely unprotected.** Chrome extensions don't run on iOS or Android. ChatGPT's mobile app, Perplexity's app, any mobile browser - Armorly cannot help you there. You're on your own.

2. **Server-side ad injection cannot be blocked.** If the AI company injects ads into the response before it reaches your browser, there is no network request to block. The ad arrives as part of the "real" response. We can only detect these via content patterns (looking for "Sponsored" labels). If they remove the label, we cannot distinguish the ad from genuine content.

3. **First-party ads on ChatGPT/Claude/Gemini are the hardest to block.** When OpenAI serves ads from api.openai.com (the same domain as real responses), there's no separate ad domain to block. We rely entirely on DOM patterns and disclosure labels. If they obfuscate the disclosure, detection degrades.

4. **New ad formats will initially get through.** Ad networks evolve. When Koah or Monetzly changes their SDK function names or DOM structure, there's a window before we update patterns. This is a cat-and-mouse game.

5. **This extension does not block ads in AI responses that are genuinely useful recommendations.** If an AI recommends a product because it's actually good and doesn't take payment for the recommendation, Armorly won't remove it. We only block disclosed sponsored content and known ad SDK injections.

6. **We cannot verify if an AI recommendation is paid but undisclosed.** If an AI company accepts payment to recommend products but doesn't label them as sponsored (illegal under FTC rules, but enforcement is slow), we have no way to detect this. We're not mind readers.

7. **Safari, Firefox, and Edge are not supported yet.** Chrome/Chromium only for now.

8. **Ad-patterns.js requires manual updates.** There's no auto-update mechanism. When ad networks change patterns, you need a new version of the extension.

9. **Iframes may bypass content script injection.** If an AI chatbot loads in a cross-origin iframe with restrictive headers, our content scripts may not inject. This is rare but possible.

10. **We cannot block ads you explicitly request.** If you ask an AI "recommend me a hotel in Tokyo" and it gives you a paid recommendation, that's indistinguishable from a genuine recommendation you asked for. We block unsolicited sponsored content, not answers to your questions.

11. **Rate of false positives is non-zero.** Legitimate content containing words like "Sponsored" or "Ad" in certain contexts may be incorrectly flagged. We err on the side of blocking, which means occasional false positives on edge cases.

12. **No network-level blocking.** Armorly deliberately does not block network requests. This is by design - use uBlock Origin or Brave for network-level ad blocking. Armorly handles client-side AI ads that those tools cannot detect.

## Why Traditional Ad Blockers Fail

Traditional ad blockers use domain-based blocking:
- Block requests to `doubleclick.net` or `ads.example.com`
- Hide elements with CSS selectors like `##.ad-container`

AI ads bypass this entirely:
- Ad content comes from the same API as real content (e.g., api.openai.com)
- No separate ad domain to block
- LLM generates ad text dynamically, no consistent HTML structure
- By the time it reaches the DOM, it's indistinguishable from organic responses

Armorly uses multi-signal detection:
1. SDK interception (block Koah, Monetzly, Sponsored.so, etc. globals)
2. FTC-required disclosure patterns ("Sponsored", "Ad", etc.)
3. Affiliate link cleaning
4. Platform-specific DOM selectors

## Supported Platforms

Works on all websites. Platform-specific detection for:
- ChatGPT/OpenAI (prepared for upcoming ads)
- Grok/X (active promoted suggestions)
- Perplexity AI (active sponsored questions)
- Claude, Gemini, Poe
- Any chatbot using Koah, Monetzly, Sponsored.so, or other ad SDKs

## Installation

### From Chrome Web Store

Coming soon. In the meantime, use the development build below.

### Development Build

```bash
git clone https://github.com/yourusername/armorly.git
cd armorly
./build.sh
```

Then in Chrome:
1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `build` folder

## Project Structure

```
armorly-dev/
├── extension/
│   ├── manifest.json
│   ├── icons/
│   ├── content/
│   │   ├── ai-ad-blocker.js
│   │   └── hidden-content-blocker.js
│   └── lib/
│       └── ad-patterns.js
├── build.sh
├── roadmap.txt
└── deploy.txt
```

### Key Files

| File | Purpose |
|------|---------|
| `ai-ad-blocker.js` | SDK interception, DOM removal, affiliate link cleaning |
| `hidden-content-blocker.js` | Hidden prompt injection detection - conservative, pattern-based |
| `ad-patterns.js` | 6 SDK definitions, 15 affiliate params, 19 redirect domains, 7 platform selectors |

## Technical Details

### Permissions

| Permission | Why |
|------------|-----|
| `<all_urls>` (host) | Inject content scripts on all sites to detect ads |

That's it. One permission. No `storage`, no `tabs`, no `webRequest`, no `cookies`, no `history`.

### Performance

- 3 files: 2 content scripts + 1 pattern library
- MutationObserver with debouncing (100-500ms)
- No persistent storage
- No network interception (leaves that to uBlock/Brave)
- No DOM method overrides (appendChild/insertBefore untouched)
- Minimal CPU impact

## Privacy

- No data sent to external servers
- No telemetry
- No analytics
- No user tracking
- All processing happens in-browser
- Open source and auditable
