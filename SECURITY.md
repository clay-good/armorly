# Security Policy

Armorly runs on every page you visit and sees the prompts you send to AI chatbots. We take security reports seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, email **hi@claygood.com** with:

- A description of the issue and its impact.
- Steps to reproduce (URL, page state, exact actions).
- A proof-of-concept if you have one.
- Your name / handle for credit, if you'd like it.

You can expect:

- An acknowledgement within **3 business days**.
- A status update within **7 days** of acknowledgement.
- A fix or mitigation plan before any public disclosure.

## Scope

In scope:

- The published Chrome Web Store build of Armorly.
- The contents of this repository, including the build script and pattern library.
- Anything that could leak user data, bypass the prompt-injection shield, or let a page detect Armorly users.

Out of scope:

- Bugs in third-party AI chatbots themselves (report those to the chatbot vendor).
- Missed ads or false positives — please use the issue templates instead.
- Issues that require the user to install another malicious extension first.

## Supported versions

Only the latest published version on the Chrome Web Store receives security fixes. We do not ship backported patches to older versions.
