# Contributing to AI SOC Analyzer

Thank you for your interest in contributing! Here's how to get involved.

---

## 🐛 Reporting Bugs

1. Check [existing issues](../../issues) first
2. Open a new issue with:
   - Python version (`python --version`)
   - OS and version
   - Full error traceback
   - Relevant settings (redact any API keys or IPs if needed)

---

## 💡 Suggesting Features

Open an issue with the **enhancement** label and describe:
- What problem it solves
- How you'd expect it to work
- Whether you'd like to implement it yourself

---

## 🔧 Pull Requests

1. Fork the repo and create a branch: `git checkout -b feature/your-feature`
2. Keep changes focused — one feature or fix per PR
3. Test against a real or simulated network before submitting
4. Update `CHANGELOG.md` under an `[Unreleased]` section
5. Open the PR with a clear description of what changed and why

---

## 📋 Code Style

- Follow existing style (no external formatter enforced)
- Keep all settings in the **SETTINGS block** at the top of `ai_soc.py`
- New integrations should be guarded by an `_ENABLED` flag defaulting to `False`
- All HTTP calls must go through `safe_request()` or use explicit per-exception handlers
- Never store API keys or passwords in the codebase — keep them in the settings block with placeholder strings

---

## 🔐 Security Issues

Please do **not** open a public issue for security vulnerabilities.  
Email the maintainer directly or use GitHub's private security advisory feature.