# Armorly

**The ad blocker for AI chatbots and agents.** Get the answer, not the ad.

[![build](https://github.com/clay-good/armorly/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/clay-good/armorly/actions/workflows/build.yml)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Armorly removing a sponsored card from a ChatGPT-style answer](docs/demo.gif)

<sup>Recorded by [`npm run demo`](tests/extension.spec.ts) on a ChatGPT-styled test page.</sup>

**[Add to Chrome](https://chromewebstore.google.com/detail/armorly/ojjmbhddhccnnepgojahamfilcpfddbp)** · free, open source, no account, no tracking.

## Why

AI is supposed to give you the best answer. Ads pay it to give you a different one. A new wave of ad networks now auctions placements inside chatbot answers and agent workflows, and a regular ad blocker can't see them: the ad arrives in the same response as the answer, from the same server.

Armorly can.

## What it blocks

| Where the ad hides | What Armorly does |
|---|---|
| **Inside the response data** (server-side, OpenRTB) | Strips ad objects out of the chatbot's own JSON, streaming and WebSocket responses before the page ever sees them. |
| **In the answer on screen** | Hides sponsored cards, promoted follow-ups and ad links by their disclosure label, in about 30 languages and through common disguises. Browser agents reading the page don't see them either. |
| **"The ad was shown" pings** | Blocks the impression and view confirmations advertisers pay for. |
| **Ad network scripts** | Blocks AI ad SDKs and their domains before they load. |
| **Your links** | Strips affiliate tags and tracking parameters from outbound links. |

**Bonus:** removes hidden prompt-injection text ("ignore previous instructions…") from web pages, so it can't sneak into what you paste into an AI.

Works on ChatGPT, Perplexity, Copilot, Gemini, Claude, Grok, Meta AI and any site serving AI ads. Detection is tested against the real ad formats of today's AI ad networks.

## Built to be trusted

- **Deterministic.** Fixed rules. No AI model guessing what's an ad.
- **Private.** Nothing leaves your browser. No telemetry, no analytics.
- **Safe for chat apps.** Ads are hidden, not ripped out, so answers keep streaming normally. One click turns it off for any site.
- **Open source.** Every rule is in this repo.

## Install

| Browser | How |
|---|---|
| Chrome, Brave | [Chrome Web Store](https://chromewebstore.google.com/detail/armorly/ojjmbhddhccnnepgojahamfilcpfddbp) |
| Edge, Firefox, Opera | Zip from the [latest release](https://github.com/clay-good/armorly/releases/latest) (store listings pending) |
| Safari | Source bundle from the latest release (build with Xcode) |

Click the Armorly icon to see what it blocked on the current page.

## Honest limits

- Desktop browsers only. Mobile apps can't run extensions.
- An ad written into the answer's own words, with no label and no ad data, can't be told apart from the answer.
- Ad views counted only on the ad platform's server can't be stopped from the browser.
- Armorly focuses on AI. Pair it with uBlock Origin for the rest of the web.

## For developers

```bash
git clone https://github.com/clay-good/armorly.git && cd armorly
npm install && npx playwright install chromium
./build.sh        # build/ → chrome://extensions → Load unpacked
npm test          # unit + headless end-to-end tests
```

Runbooks: [tests](tests/README.md) · [releasing](docs/RELEASING.md) · [adding an ad network](CONTRIBUTING.md) · [security](SECURITY.md) · [changelog](CHANGELOG.md)

## License

MIT, see [LICENSE](LICENSE).
