# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

A collection of Claude Code skills for HarmonyOS / OpenHarmony development. Each skill is a standalone directory under `skills/` containing a `SKILL.md` (skill metadata + triggers) and optionally a `scripts/` directory with tooling.

## Skills Structure

```
skills/
├── <skill-name>/
│   ├── SKILL.md         # Required — skill metadata (name, description, triggers, tags)
│   └── scripts/          # Optional — automation scripts invoked by Claude
│       └── ...
```

### SKILL.md Frontmatter Fields

- `name` — kebab-case slug, used by `npx skills add <name>`
- `description` — one-liner shown in skill list
- `triggers` — phrases that cause Claude to invoke this skill
- `tags` — categorization keywords
- `license` — SPDX identifier

## Skill Design Rules

1. **Self-contained**: Each skill must be installable independently via `npx skills add github:owner/repo/skills/<name>`.
2. **Scripts**: Prefer cross-platform (Python) over platform-specific (PowerShell/Bash). Include fallback: `hap_analyze.py` is primary, `.ps1`/`.sh` are platform-specific alternatives.
3. **Error handling**: Scripts should fail gracefully (e.g., `--no-asm` mode when `ark_disasm.exe` unavailable) and surface clear troubleshooting hints.
4. **HarmonyOS SDK paths**: Never hardcode a single path — search common install locations (DevEco Studio SDK toolchains) and `$PATH`/`%PATH%`.

## Current Skills

| Skill | Entry | Scripts |
|-------|-------|---------|
| **hap-install** | `skills/hap-install/SKILL.md` | `scripts/hdc-install.sh` — Bash, deploys HAP to device via `hdc` |
| **hap-decompile** | `skills/hap-decompile/SKILL.md` | `scripts/hap_analyze.py` (primary), `.ps1`, `.sh` — extracts & analyzes HAP packages |

## Key Dependencies

- **hdc**: HarmonyOS device bridge (DevEco Studio SDK toolchains)
- **ark_disasm.exe**: `.abc` → `.asm` disassembler (DevEco Studio SDK, Windows PE only)
- **Python 3**: Required by hap_analyze.py

## Adding a New Skill

1. Create `skills/<name>/SKILL.md` with valid frontmatter (name, description, triggers, tags)
2. Add scripts under `skills/<name>/scripts/` if needed
3. Test locally: `npx skills add ./skills/<name>`
4. Add the skill to README.md overview table

## Testing

- Install the skill locally: `npx skills add ./skills/<name>`
- Verify Claude triggers on the listed trigger phrases
- For scripts, run directly with `--help` to confirm argument parsing
