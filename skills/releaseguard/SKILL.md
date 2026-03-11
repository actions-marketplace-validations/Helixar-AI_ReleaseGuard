---
name: releaseguard
description: Scan, harden, sign, and verify release artifacts with ReleaseGuard — the artifact policy engine for dist/ and release/ outputs.
homepage: https://github.com/Helixar-AI/ReleaseGuard
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["releaseguard"]}}}
---

# ReleaseGuard Skill

ReleaseGuard is an artifact policy engine. Use it to scan build outputs for secrets, misconfigurations, and supply-chain risks; harden and fix them; generate SBOMs; sign artifacts; and verify release integrity.

## Install ReleaseGuard

If `releaseguard` is not installed, install it first:

```bash
curl -sSfL https://raw.githubusercontent.com/Helixar-AI/ReleaseGuard/main/scripts/install.sh | sh
```

Or via Homebrew:

```bash
brew install Helixar-AI/tap/releaseguard
```

---

## Commands

### Check / Scan — `releaseguard check <path>`

Scan an artifact path and evaluate the release policy.

**Trigger phrases:** "scan", "check", "audit", "analyze release", "inspect dist", "any secrets", "find vulnerabilities"

```bash
releaseguard check <path>
releaseguard check <path> --format json
releaseguard check <path> --format sarif --out results.sarif
releaseguard check <path> --format markdown --out report.md
```

- Default format: `cli` (human-readable, coloured)
- Other formats: `json`, `sarif`, `markdown`, `html`
- Use `--out <file>` to write output to a file instead of stdout
- Exit code 0 = PASS, non-zero = FAIL (use in CI gates)

**Workflow:** Run `releaseguard check` first. If it fails, run `releaseguard fix` to apply deterministic hardening, then re-check.

---

### Fix — `releaseguard fix <path>`

Apply safe, deterministic hardening transforms to an artifact path.

**Trigger phrases:** "fix", "harden", "apply fixes", "remediate", "auto-fix release"

```bash
releaseguard fix <path>
releaseguard fix <path> --dry-run   # preview without applying
```

- `--dry-run` shows what would change without modifying files
- Always preview with `--dry-run` before applying to production artifacts

---

### SBOM — `releaseguard sbom <path>`

Generate a Software Bill of Materials for the artifact.

**Trigger phrases:** "sbom", "software bill of materials", "dependencies", "generate bom", "list components"

```bash
releaseguard sbom <path>
releaseguard sbom <path> --format spdx --out sbom.spdx.json
releaseguard sbom <path> --enrich-cve   # fetch CVE data from OSV.dev
```

- Default format: `cyclonedx` (outputs `.releaseguard/sbom.cdx.json`)
- Other format: `spdx`
- `--enrich-cve` fetches live vulnerability data from OSV.dev

---

### Obfuscate — `releaseguard obfuscate <path>`

Apply obfuscation to release artifacts.

**Trigger phrases:** "obfuscate", "strip symbols", "protect binary", "encrypt strings"

```bash
releaseguard obfuscate <path> --level light
releaseguard obfuscate <path> --level medium
releaseguard obfuscate <path> --dry-run
```

Levels:
- `none` — no obfuscation
- `light` — symbol strip, string encrypt, basic mangling (OSS)
- `medium` — + control flow flatten, bytecode transform (Cloud)
- `aggressive` — + opaque predicates, LLVM passes (Cloud)

---

### Harden — `releaseguard harden <path>`

Full hardening pipeline: fix + obfuscate + DRM injection in one command.

**Trigger phrases:** "full harden", "harden release", "full hardening pipeline"

```bash
releaseguard harden <path>
releaseguard harden <path> --obfuscation medium --dry-run
```

---

### Pack — `releaseguard pack <path>`

Package an artifact into a canonical archive.

**Trigger phrases:** "pack", "package artifact", "create archive", "bundle release"

```bash
releaseguard pack <path> --out release.tar.gz
releaseguard pack <path> --out release.zip --format zip
```

- `--out` is required
- Formats: `tar.gz` (default), `zip`

---

### Sign — `releaseguard sign <artifact>`

Sign an artifact and its evidence bundle.

**Trigger phrases:** "sign", "cosign", "keyless sign", "sign artifact", "add signature"

```bash
releaseguard sign <artifact>                       # keyless (Sigstore)
releaseguard sign <artifact> --mode local --key signing.key
```

- Default mode: `keyless` via Sigstore (requires OIDC token in CI)
- `local` mode: provide a private key file with `--key`

---

### Attest — `releaseguard attest <artifact>`

Emit in-toto and SLSA provenance attestations.

**Trigger phrases:** "attest", "provenance", "slsa", "in-toto", "generate attestation"

```bash
releaseguard attest <artifact>
```

---

### Verify — `releaseguard verify <artifact>`

Verify artifact signatures and policy compliance.

**Trigger phrases:** "verify", "check signature", "validate artifact", "is this signed"

```bash
releaseguard verify <artifact>
```

---

### Report — `releaseguard report <path>`

Export a scan report in a specified format.

**Trigger phrases:** "report", "export report", "generate report", "compliance report"

```bash
releaseguard report <path>
releaseguard report <path> --format sarif --out results.sarif
releaseguard report <path> --format html --out report.html
```

- Formats: `json` (default), `cli`, `sarif`, `markdown`, `html`

---

### VEX — `releaseguard vex <path>`

Enrich an SBOM with VEX (Vulnerability Exploitability eXchange) data.

**Trigger phrases:** "vex", "vulnerability data", "enrich sbom", "exploitability"

```bash
releaseguard vex <path> --sbom .releaseguard/sbom.cdx.json --out vex.json
```

---

## Typical Workflows

### Full release pipeline
```bash
releaseguard check ./dist        # scan for issues
releaseguard fix ./dist          # apply deterministic hardening
releaseguard sbom ./dist         # generate SBOM
releaseguard pack ./dist --out release.tar.gz
releaseguard sign release.tar.gz
releaseguard attest release.tar.gz
releaseguard verify release.tar.gz
```

### Quick scan + report
```bash
releaseguard check ./dist --format markdown --out scan-report.md
```

### CI gate (fail on policy violation)
```bash
releaseguard check ./dist --format sarif --out results.sarif && echo "PASS" || echo "FAIL"
```

---

## Output Interpretation

- **PASS** — all policy rules satisfied, artifact is clean
- **FAIL** — one or more findings require attention; exit code is non-zero
- Findings include: category (secret, config, sbom, permission), severity (critical/high/medium/low/info), file path, line number, and remediation hint
- Use `releaseguard fix` to auto-remediate safe findings, then re-run `releaseguard check`

---

## Configuration

ReleaseGuard reads `.releaseguard.yml` in the current directory. Initialize it with:

```bash
releaseguard init
```

Key config options:
```yaml
scanning:
  exclude_paths:
    - test/fixtures
    - examples
policy:
  fail_on: [critical, high]
```
