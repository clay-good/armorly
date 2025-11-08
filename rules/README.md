# Armorly Blocking Rules

## ⚠️ PROOF OF CONCEPT - LIMITED PROTECTION ⚠️

This directory contains declarativeNetRequest rules for blocking malicious requests. **These rules provide only basic, demonstration-level protection and are NOT sufficient for production use.**

## Current Rules (15 total)

### CSRF Protection (Rules 1-4)
- Blocks unauthorized cross-origin requests to AI service APIs
- **ChatGPT Memory API** - Prevents CSRF attacks on chat.openai.com and chatgpt.com memory endpoints
- **Perplexity API** - Protects perplexity.ai user data
- **Claude AI API** - Protects claude.ai conversation endpoints

### Malicious TLD Blocking (Rules 5-9)
- Blocks high-risk free domain TLDs frequently used in attacks:
  - `.tk` (Tokelau)
  - `.ml` (Mali)
  - `.ga` (Gabon)
  - `.cf` (Central African Republic)
  - `.gq` (Equatorial Guinea)

### Data Exfiltration Prevention (Rules 10-12)
- **pastebin.com/raw** - Blocks raw pastebin access (commonly used for exfiltration)
- **transfer.sh** - Blocks anonymous file sharing
- **anonfiles.com** - Blocks anonymous file hosting

### Injection Prevention (Rules 13-15)
- Blocks `eval()` in scripts
- Blocks `javascript:` protocol in frames
- Blocks `data:text/html` with embedded scripts

## ❌ Removed Fake Rules

Previous versions included rules for fake domains (evil.com, malware.com, phishing.com, attacker.com, malicious.com). These have been **removed** as they provided no real protection and were misleading placeholder data.

## 🚨 For Production Use

To provide real protection, you need:

### 1. Comprehensive Threat Intelligence
- **abuse.ch** (URLhaus) - 100k+ malicious URLs updated daily
- **PhishTank** - 50k+ verified phishing URLs
- **OpenPhish** - Real-time phishing feed
- **CERT feeds** - Government threat intelligence
- **Commercial feeds** - Paid threat intelligence services

### 2. Dynamic Rule Updates
Implement auto-update mechanism using:
```javascript
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [...],
  removeRuleIds: [...]
});
```

### 3. Machine Learning
- Anomaly detection for zero-day threats
- URL pattern analysis
- Behavioral analytics

### 4. Community Reporting
- User-reported threats
- Crowdsourced threat intelligence
- Integration with security communities

## Current Limitations

| Metric | Current | Needed for Production |
|--------|---------|----------------------|
| Total Rules | 15 | 10,000+ |
| Malicious Domains | ~10 | 1,000,000+ |
| Update Frequency | Never | Hourly |
| False Positive Rate | Unknown | <0.01% |
| Detection Rate | <1% | >95% |

## How to Extend

1. **Add new rules** to `csrf-rules.json` following the schema
2. **Test thoroughly** to avoid false positives
3. **Document** each rule's purpose
4. **Monitor** effectiveness and adjust as needed

## Schema Reference

```json
{
  "id": 16,
  "priority": 1,
  "action": { "type": "block" },
  "condition": {
    "urlFilter": "*://example.com/*",
    "resourceTypes": ["main_frame"]
  }
}
```

## Important Notes

- **Rule ID must be unique** (1-999 reserved for static rules, 1000+ for dynamic)
- **Lower priority = executed first** (1 is highest priority)
- **Test in development** before deploying to users
- **Monitor for false positives** and user complaints

---

**Last Updated**: 2025-01-08
**Rules Version**: 2.0 (Removed fake domains, added disclaimer)
**Effective Protection**: Demonstration only - integrate real threat feeds for production
