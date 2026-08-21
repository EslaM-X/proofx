# ProofX Brand Guidelines

## Brand Identity

**ProofX** — Cryptographically verifiable evidence for software.

**Tagline:** VERIFY. TRUST. PROVE.

## Logo Usage

### Primary Logo
- **Dark background:** `brand/logo/proofx-logo-dark.svg`
- **Light background:** `brand/logo/proofx-logo-light.svg`
- Use when there is sufficient horizontal space

### Symbol Mark
- **Dark:** `brand/symbol/proofx-symbol-dark.svg`
- **Light:** `brand/symbol/proofx-symbol-light.svg`
- Use for: GitHub avatar, favicon, npm icon, PyPI icon, app icons

### Verification Badge
- `brand/badges/proof-verified-dark.svg`
- Use for: README badges, verification seals, community

### Favicon
- `brand/favicon/favicon.svg`

## Color Palette

### Primary Colors
| Color | Hex | Usage |
|-------|-----|-------|
| **Cyan** | `#00D4FF` | Primary accent, links, highlights |
| **Teal** | `#00FFD0` | Secondary accent, gradients |
| **Green** | `#00FF88` | Success, verified, checkmarks |

### Background Colors
| Color | Hex | Usage |
|-------|-----|-------|
| **Dark Navy** | `#0A0E17` | Primary background |
| **Dark Gray** | `#111827` | Secondary background |
| **Slate** | `#1E293B` | Borders, dividers |

### Text Colors
| Color | Hex | Usage |
|-------|-----|-------|
| **White** | `#FFFFFF` | Primary text on dark |
| **Light Gray** | `#94A3B8` | Secondary text |
| **Muted** | `#64748B` | Tertiary text |

## Gradient

```css
background: linear-gradient(135deg, #00D4FF, #00FFD0);
```

## Typography

- **Font Family:** SF Pro Display, Inter, Segoe UI, system-ui, sans-serif
- **Font Weight:** 700 (bold) for headings, 400 (regular) for body
- **Letter Spacing:** 2px for PROOFX, 4px for tagline

## Symbol Meaning

| Element | Meaning |
|---------|---------|
| Shield | Security / Trust |
| Cube | Evidence / Data |
| Checkmark | Verification |
| Lock | Cryptographic protection |
| Ascending pixels | Data / Reproducibility |

## Brand Positioning

**ProofX** is not just a security tool. It is **proof infrastructure** for software.

- Evidence → Claims → Merkle binding → Commitment → Ed25519 → Proof → Independent verification
- Available as: CLI, GitHub Action, WASM, Browser verification
- Works with: CI/CD, AI agents, robotics, security audits

## Files

```
brand/
├── logo/
│   ├── proofx-logo-dark.svg      Primary logo (dark)
│   └── proofx-logo-light.svg     Primary logo (light)
├── symbol/
│   ├── proofx-symbol-dark.svg    Symbol (dark)
│   └── proofx-symbol-light.svg   Symbol (light)
├── favicon/
│   └── favicon.svg               Favicon
├── badges/
│   ├── proof-verified-dark.svg   Verification badge (dark)
│   └── proof-verified-badge.svg  README badge
└── BRAND.md                      This file
```

## Copyright

Copyright (c) 2026 EslaM-X. All rights reserved.
