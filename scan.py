#!/usr/bin/env python3
"""
AgenticQA Architecture Scanner
Maps every integration point in a codebase across 13 CWE categories.
https://github.com/nhomyk/agenticqa-scan-action
"""
import json
import os
import sys
from pathlib import Path

MINIMAL_SARIF = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "AgenticQA Architecture Scanner",
                "version": "1.0.0",
                "informationUri": "https://github.com/nhomyk/agenticqa-scan-action",
                "rules": []
            }
        },
        "results": []
    }]
}

# Category → CWE mapping (for SARIF rule descriptions)
_CWE_MAP = {
    "SHELL_EXEC":      "CWE-78",
    "EXTERNAL_HTTP":   "CWE-918",
    "DATABASE":        "CWE-89",
    "FILE_SYSTEM":     "CWE-73",
    "ENV_SECRETS":     "CWE-798",
    "SERIALIZATION":   "CWE-502",
    "NETWORK_SOCKET":  "CWE-601",
    "CLOUD_SERVICE":   "CWE-306",
    "AUTH_BOUNDARY":   "CWE-306",
    "MIDDLEWARE":      "CWE-284",
    "EVENT_BUS":       "CWE-400",
    "MCP_TOOL":        "CWE-284",
    "AGENT_FRAMEWORK": "CWE-693",
}

repo_path = os.environ.get('SCAN_REPO_PATH', '.')
sarif_output = os.environ.get('SARIF_OUTPUT', 'agenticqa-scan-results.sarif')
fail_on_critical = os.environ.get('FAIL_ON_CRITICAL', 'false').lower() == 'true'
fail_on_score_str = os.environ.get('FAIL_ON_SCORE', '0')
try:
    fail_on_score = int(fail_on_score_str)
except ValueError:
    fail_on_score = 0

total_findings = 0
critical_count = 0
attack_surface_score = 0.0
test_coverage = 0.0
untested_count = 0
categories = {}
scan_result = None


# ── Run Architecture Scan ─────────────────────────────────────────────────────
print("🔍 Running AgenticQA Architecture Scan...")
print(f"   Repo: {Path(repo_path).resolve()}")

try:
    from agenticqa.security.architecture_scanner import ArchitectureScanner

    scan_result = ArchitectureScanner().scan(repo_path)

    if scan_result.scan_error:
        print(f"   Scan error: {scan_result.scan_error}", file=sys.stderr)
    else:
        total_findings = scan_result.total_findings
        critical_count = len(scan_result.critical_areas)
        attack_surface_score = scan_result.attack_surface_score
        test_coverage = scan_result.test_coverage_confidence
        untested_count = len(scan_result.untested_areas)
        categories = scan_result.category_counts

        print(f"   Files scanned:          {scan_result.files_scanned}")
        print(f"   Integration areas:      {total_findings}")
        print(f"   Critical areas:         {critical_count}")
        print(f"   Attack surface score:   {attack_surface_score:.0f}/100")
        print(f"   Test coverage:          {test_coverage:.0f}%")
        print(f"   Untested areas:         {untested_count}")

        if categories:
            print("\n   Categories detected:")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                cwe = _CWE_MAP.get(cat, '')
                cwe_str = f" ({cwe})" if cwe else ''
                print(f"   • {cat}{cwe_str}: {count}")

except ImportError as e:
    print(f"   ArchitectureScanner not available: {e}", file=sys.stderr)
except Exception as e:
    print(f"   Architecture scan error: {e}", file=sys.stderr)


# ── Export to SARIF ───────────────────────────────────────────────────────────
print(f"\n📄 Writing SARIF → {sarif_output}")
sarif_count = 0

try:
    from agenticqa.export.sarif import SARIFExporter

    exporter = SARIFExporter(repo_root=repo_path)
    sev_map = {'critical': 'error', 'high': 'warning', 'medium': 'note', 'low': 'note'}

    if scan_result and not scan_result.scan_error:
        for area in scan_result.integration_areas:
            rule_id = f'ARCH_{area.category}'
            cwe = _CWE_MAP.get(area.category, '')
            cwe_str = f" ({cwe})" if cwe else ''
            vectors = ', '.join(area.attack_vectors[:3]) if area.attack_vectors else 'unknown'
            tested_str = 'TESTED' if area.test_files else 'NO TESTS'

            message = (
                f'{area.category}{cwe_str} in {area.source_file}:{area.line_number} [{tested_str}]. '
                f'{area.plain_english[:120]} '
                f'Attack vectors: {vectors}.'
            )

            exporter._add(
                rule_id,
                message,
                area.source_file,
                area.line_number,
                severity=sev_map.get(area.severity, 'note'),
                rule_desc=(
                    f'Architecture integration point: {area.category}{cwe_str}. '
                    f'Attack vectors: {vectors}.'
                ),
            )
            sarif_count += 1

    exporter.write(sarif_output)
    print(f"   {sarif_count} finding(s) written to SARIF")

except Exception as e:
    print(f"   SARIF export error ({e}) — writing fallback", file=sys.stderr)
    with open(sarif_output, 'w') as fh:
        json.dump(MINIMAL_SARIF, fh)


# ── GitHub Step Summary ───────────────────────────────────────────────────────
summary_file = os.environ.get('GITHUB_STEP_SUMMARY', '')
if summary_file:
    score = int(attack_surface_score)
    if score >= 75:
        score_icon = '🔴'
    elif score >= 50:
        score_icon = '🟠'
    elif score >= 25:
        score_icon = '🟡'
    else:
        score_icon = '🟢'

    lines = [
        f'## {score_icon} AgenticQA Architecture Scan — Score {score}/100',
        '',
        f'**Integration areas found:** {total_findings} &nbsp;|&nbsp; '
        f'**Critical:** {critical_count} &nbsp;|&nbsp; '
        f'**Untested:** {untested_count}  ',
        f'**Attack surface score:** {attack_surface_score:.0f}/100 &nbsp;|&nbsp; '
        f'**Test coverage confidence:** {test_coverage:.0f}%  ',
        '',
    ]

    if critical_count > 0:
        lines += [
            f'> ⚠️ **{critical_count} critical area(s) detected** — '
            f'SHELL_EXEC and similar RCE-class integration points require immediate review.',
            '',
        ]

    if categories:
        lines += [
            '| Category | Count | CWE | Severity |',
            '|----------|-------|-----|----------|',
        ]

        # Severity order for display
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        _CAT_SEV = {
            'SHELL_EXEC': 'critical', 'EXTERNAL_HTTP': 'high', 'DATABASE': 'high',
            'ENV_SECRETS': 'high', 'SERIALIZATION': 'high', 'NETWORK_SOCKET': 'high',
            'AGENT_FRAMEWORK': 'high', 'CLOUD_SERVICE': 'medium', 'AUTH_BOUNDARY': 'medium',
            'MIDDLEWARE': 'medium', 'EVENT_BUS': 'low', 'MCP_TOOL': 'medium',
            'FILE_SYSTEM': 'medium',
        }
        for cat, count in sorted(
            categories.items(),
            key=lambda x: (sev_order.get(_CAT_SEV.get(x[0], 'low'), 99), -x[1])
        ):
            cwe = _CWE_MAP.get(cat, '—')
            sev = _CAT_SEV.get(cat, 'info')
            sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(sev, '⚪')
            lines.append(f'| `{cat}` | {count} | {cwe} | {sev_icon} {sev} |')

    if untested_count > 0 and scan_result and not scan_result.scan_error:
        untested_critical = [a for a in scan_result.untested_areas if a.severity in ('critical', 'high')]
        if untested_critical:
            lines += [
                '',
                f'**Top untested high-risk areas** ({len(untested_critical)} total):',
                '',
            ]
            for a in untested_critical[:5]:
                lines.append(f'- `{a.source_file}:{a.line_number}` — {a.category}')
            if len(untested_critical) > 5:
                lines.append(f'- … and {len(untested_critical) - 5} more')

    lines += [
        '',
        '*Powered by [AgenticQA](https://github.com/nhomyk/AgenticQA) · '
        '[agenticqa-scan-action](https://github.com/nhomyk/agenticqa-scan-action)*',
    ]

    with open(summary_file, 'a') as fh:
        fh.write('\n'.join(lines) + '\n')


# ── GitHub Output Variables ───────────────────────────────────────────────────
github_output = os.environ.get('GITHUB_OUTPUT', '')
if github_output:
    with open(github_output, 'a') as fh:
        fh.write(f'findings_count={total_findings}\n')
        fh.write(f'critical_count={critical_count}\n')
        fh.write(f'attack_surface_score={int(attack_surface_score)}\n')
        fh.write(f'test_coverage={int(test_coverage)}\n')
        fh.write(f'untested_count={untested_count}\n')


# ── Summary ───────────────────────────────────────────────────────────────────
print(
    f'\n📊 Score: {attack_surface_score:.0f}/100 | '
    f'Areas: {total_findings} | Critical: {critical_count} | '
    f'Untested: {untested_count} | Coverage: {test_coverage:.0f}%'
)

if critical_count > 0:
    print('⚠️  Critical integration areas detected — SHELL_EXEC and similar RCE vectors require review')


# ── Exit code ─────────────────────────────────────────────────────────────────
exit_code = 0

if fail_on_critical and critical_count > 0:
    print(f'\n❌ Failing: {critical_count} critical area(s) and fail-on-critical=true')
    exit_code = 1

if fail_on_score > 0 and int(attack_surface_score) >= fail_on_score:
    print(
        f'\n❌ Failing: attack surface score {int(attack_surface_score)} '
        f'>= threshold {fail_on_score}'
    )
    exit_code = 1

if exit_code == 0:
    print('\n✅ Architecture scan complete')

sys.exit(exit_code)
