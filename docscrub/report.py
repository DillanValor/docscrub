"""Findings report generation (markdown)."""

from collections import Counter
from datetime import datetime, timezone

SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Plain-English meanings for placeholder tokens — used by the GUI legend
# and the legend.csv export.
FRIENDLY_LABELS = {
    "PERSON": "Person name",
    "ORG": "Organization / client name",
    "LOCATION": "Location",
    "EMAIL": "Email address",
    "PHONE": "Phone number",
    "US_SSN": "Social Security number",
    "CREDIT_CARD": "Credit card number",
    "CARD_NUMBER": "Card-shaped number",
    "IBAN": "Bank account (IBAN)",
    "PASSPORT": "Passport number",
    "DRIVER_LICENSE": "Driver's license number",
    "INTERNAL_IP": "Internal IP address",
    "PUBLIC_IP": "Public IP address",
    "INTERNAL_FQDN": "Internal domain name",
    "HOSTNAME": "Device hostname",
    "UNC_PATH": "File share path (UNC)",
    "MAC_ADDRESS": "MAC address",
    "GUID": "GUID / tenant ID",
    "PRIVATE_KEY": "Private key block",
    "AWS_KEY": "AWS access key",
    "GITHUB_TOKEN": "GitHub token",
    "SLACK_TOKEN": "Slack token",
    "GOOGLE_API_KEY": "Google API key",
    "AZURE_KEY": "Azure storage key",
    "JWT": "Session token (JWT)",
    "SECRET_VALUE": "API key / secret",
    "CONNECTION_SECRET": "Connection-string password",
}


def friendly_label(entity_type):
    return FRIENDLY_LABELS.get(entity_type,
                               entity_type.replace("_", " ").title())


def _mask(value, severity):
    """Never print a full secret back into the report."""
    if severity == "critical":
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"
    if len(value) > 60:
        return value[:57] + "…"
    return value


def build_report(source_file, out_file, findings, mapping):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    unique = {}
    for f in findings:
        unique.setdefault(f.token, f)

    by_sev = Counter(f.severity for f in findings)
    by_type = Counter(f.entity_type for f in findings)

    lines = [
        "# DocScrub Findings Report",
        "",
        f"- **Source:** `{source_file}`",
        f"- **Sanitized output:** `{out_file}`",
        f"- **Scanned:** {ts}",
        f"- **Total redactions:** {len(findings)} "
        f"({len(unique)} unique values)",
        "",
        "## Summary by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in sorted(by_sev, key=lambda s: SEVERITY_ORDER[s]):
        lines.append(f"| {SEVERITY_ICONS[sev]} {sev} | {by_sev[sev]} |")

    lines += ["", "## Summary by type", "", "| Type | Occurrences |", "|---|---|"]
    for etype, count in by_type.most_common():
        lines.append(f"| {etype} | {count} |")

    lines += [
        "",
        "## Unique values redacted",
        "",
        "| Token | Type | Severity | Value (masked) | Detected by |",
        "|---|---|---|---|---|",
    ]
    for token, f in sorted(unique.items(),
                           key=lambda kv: (SEVERITY_ORDER[kv[1].severity], kv[0])):
        lines.append(
            f"| `{token}` | {f.entity_type} | {SEVERITY_ICONS[f.severity]} "
            f"{f.severity} | `{_mask(f.text, f.severity)}` | {f.layer} |"
        )

    lines += [
        "",
        "---",
        "",
        "**Handling notes**",
        "",
        "- The sanitized document is safe to share with an AI assistant; "
        "tokens are consistent, so the AI's reasoning stays coherent.",
        "- `mapping.json` reverses the tokens (`rehydrate` command). "
        "Treat it as sensitive — it contains the original values.",
        "- 🔴 critical findings are live credentials: rotate them if this "
        "document was ever shared before sanitizing.",
    ]
    return "\n".join(lines) + "\n"
