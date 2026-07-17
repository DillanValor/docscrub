"""Detection + tokenization engine.

Three detection layers:
  1. Presidio pattern recognizers (email, phone, credit card, IBAN, URL, ...)
  2. Custom regex layer: secrets, keys, tokens, connection strings,
     IPs (internal/public), MACs, GUIDs, UNC paths, internal FQDNs, hostnames
  3. Heuristic person-name detection (context-word driven)

PoC note: person-name detection normally rides on a full spaCy NER model
(en_core_web_lg) or a transformers model. This sandbox can't download one,
so layer 3 is a context heuristic. The engine is modular — swapping the
NLP engine in `build_analyzer()` upgrades it with no other changes.
"""

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Offline hardening: Presidio's URL recognizer uses tldextract, which tries
# to refresh the public-suffix list from the network at first use. DocScrub
# promises "nothing leaves this machine", so force the bundled snapshot and
# silence the fetch machinery entirely.
# ---------------------------------------------------------------------------
try:
    import tldextract

    tldextract.extract = tldextract.TLDExtract(suffix_list_urls=())
    logging.getLogger("tldextract").setLevel(logging.CRITICAL)
except Exception:  # tldextract layout changed — worst case is a noisy log line
    pass

# --------------------------------------------------------------------------
# Severity levels
# --------------------------------------------------------------------------
CRITICAL = "critical"   # live credentials / key material
HIGH = "high"           # internal infrastructure identifiers
MEDIUM = "medium"       # PII
LOW = "low"             # contextual / heuristic matches

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


@dataclass
class Finding:
    entity_type: str
    start: int
    end: int
    text: str
    score: float
    severity: str
    layer: str          # presidio | regex | heuristic
    priority: int = 1   # higher wins on overlap
    token: str = ""
    context: str = ""

    def to_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------
# Layer 2: custom regex rules
#   (name, entity_type, severity, priority, flags, group, pattern)
# --------------------------------------------------------------------------
REGEX_RULES = [
    # --- key material & credentials (critical) ---
    ("private_key_block", "PRIVATE_KEY", CRITICAL, 10, 0, 0,
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ("aws_access_key", "AWS_KEY", CRITICAL, 9, 0, 0,
     r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github_token", "GITHUB_TOKEN", CRITICAL, 9, 0, 0,
     r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ("slack_token", "SLACK_TOKEN", CRITICAL, 9, 0, 0,
     r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    ("google_api_key", "GOOGLE_API_KEY", CRITICAL, 9, 0, 0,
     r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("jwt", "JWT", CRITICAL, 9, 0, 0,
     r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("azure_account_key", "AZURE_KEY", CRITICAL, 9, re.IGNORECASE, 1,
     r"AccountKey=([A-Za-z0-9+/]{40,}={0,2})"),
    ("conn_string_password", "CONNECTION_SECRET", CRITICAL, 8, re.IGNORECASE, 1,
     r"(?:Password|Pwd)\s*=\s*([^;\s\"']{3,}[^;\s\"'\.])"),  # no trailing '.'
    ("generic_secret_assignment", "SECRET_VALUE", CRITICAL, 7, re.IGNORECASE, 2,
     r"\b(api[_\-]?key|apikey|client[_\-]?secret|secret|token|passwd|password)\b"
     r"\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-\.=!@#$%^&*]{7,}"
     r"[A-Za-z0-9+/_\-=!@#$%^&*])[\"']?"),   # can't END on '.' — sentence periods
    ("card_shaped_number", "CARD_NUMBER", CRITICAL, 5, 0, 0,
     # card-prefixed 16-digit runs, spaces/dashes allowed. Deliberately does
     # NOT require a valid Luhn checksum (Presidio's CREDIT_CARD does) — for
     # a sanitizer, a card-shaped number is worth redacting even if mistyped.
     r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){3}\b"),

    # --- infrastructure identifiers (high) ---
    ("mac_address", "MAC_ADDRESS", HIGH, 8, 0, 0,
     r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    # Loose IPv6 candidate (handles '::' compression); ipaddress-validated in
    # _classify_ip, which discards non-IPs (times, MACs) from this rule.
    ("ipv6", "IP_ADDRESS", HIGH, 5, 0, 0,
     r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b"),
    ("ipv4", "IP_ADDRESS", HIGH, 6, 0, 0,
     r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
     r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    ("guid", "GUID", HIGH, 6, 0, 0,
     r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ("unc_path", "UNC_PATH", HIGH, 7, 0, 0,
     r"\\\\[A-Za-z0-9_\-\.]+(?:\\[A-Za-z0-9_\-\$]+(?:\.[A-Za-z0-9_\-\$]+)*)+\\?"),
    ("internal_fqdn", "INTERNAL_FQDN", HIGH, 7, re.IGNORECASE, 0,
     r"\b[A-Za-z0-9][A-Za-z0-9\-\.]*\.(?:local|lan|internal|corp|intra)\b"),
    ("hostname_convention", "HOSTNAME", HIGH, 5, 0, 0,
     r"\b[A-Z][A-Z0-9]{1,7}-(?:DC|SRV|SQL|FS|APP|HV|VM|WS|FW|NAS|RDS|EXCH|AD|BK|PRT)[0-9]{0,3}\b"),
    # Generic PREFIX-ROLE## convention (BVL-SW01, ACME-RTR2). Trailing digits
    # required, so KB/RFC/PO-style references don't match.
    ("hostname_generic", "HOSTNAME", HIGH, 5, 0, 0,
     r"\b[A-Z][A-Z0-9]{1,7}-[A-Z]{1,6}[0-9]{1,3}\b"),

    # --- PII patterns Presidio's defaults are weak on (medium) ---
    ("us_ssn_bare", "US_SSN", MEDIUM, 7, 0, 0,
     r"\b\d{3}-\d{2}-\d{4}\b"),

    # Context-free possible secret: a bare high-entropy token, e.g. an API
    # key an AI response mentions WITHOUT its original `api_key =` context
    # ("rotate the key fgt_7Hq2…"). Candidates validated in code:
    # mixed case + ≥2 digits required. Specific key rules outrank this.
    ("possible_secret", "POSSIBLE_SECRET", HIGH, 4, 0, 0,
     r"\b[A-Za-z][A-Za-z0-9_\-]{15,}\b"),
]


def _looks_like_secret(value):
    return (any(c.isupper() for c in value)
            and any(c.islower() for c in value)
            and sum(c.isdigit() for c in value) >= 2)

# Heuristic person names: context word followed by First Last.
# (?-i:...) keeps the captured name case-SENSITIVE while context words stay
# case-insensitive — requires Python 3.11+.
NAME_HEURISTIC = re.compile(
    r"(?:contact|technician|user|engineer|from|attn|approved by|requested by|"
    r"submitted by|owner|manager|mr\.|ms\.|mrs\.|dr\.)"
    r"[:\s]+((?-i:[A-Z][a-z]{1,15}\s[A-Z][a-z]{1,15}))\b",
    re.IGNORECASE,
)

# Org names by suffix — catches "Harbor Point Dental Group" with no
# "Client:" label. Prefix words are checked against ORG_STOPWORDS in code
# so "Network Security Group" / "Distribution Group" don't trip it.
ORG_SUFFIX = re.compile(
    r"\b((?:[A-Z][A-Za-z&'\.]{2,}\s+){1,4}"
    r"(?:Group|Inc\.?|LLC|Ltd\.?|Corp\.?|Partners|Associates|Solutions|"
    r"Services|Logistics|Holdings|Enterprises|Industries|Clinic|Dental|"
    r"Medical|Consulting|Agency|Insurance|Realty|Financial))\b")

ORG_STOPWORDS = {
    "local", "network", "security", "resource", "address", "domain",
    "storage", "backup", "server", "admin", "user", "group", "policy",
    "the", "this", "that", "distribution", "universal", "global", "active",
    "directory", "routing", "port", "vlan", "access", "control", "cloud",
    "managed", "azure", "microsoft", "windows", "remote", "desktop",
    "professional", "premium", "business", "enterprise", "standard",
}

# Heuristic org names: context word followed by a capitalized phrase
ORG_HEURISTIC = re.compile(
    r"(?:client|customer|company|organization|migrate|migrating|onboard(?:ing)?|offboard(?:ing)?|acquired)"
    r"[: \t]+((?-i:[A-Z][A-Za-z&'\.]+(?:[ \t](?:of|and|&|[A-Z][A-Za-z&'\.]+)){0,5}))",
    re.IGNORECASE,
)

# Presidio entities to keep, and how they map to (type, severity)
PRESIDIO_KEEP = {
    "EMAIL_ADDRESS": ("EMAIL", MEDIUM),
    "PHONE_NUMBER": ("PHONE", MEDIUM),
    "CREDIT_CARD": ("CREDIT_CARD", CRITICAL),
    "IBAN_CODE": ("IBAN", CRITICAL),
    "US_SSN": ("US_SSN", MEDIUM),
    "US_PASSPORT": ("PASSPORT", MEDIUM),
    "US_DRIVER_LICENSE": ("DRIVER_LICENSE", MEDIUM),
    # ML/NER-based — only fire when a real spaCy model is installed.
    # (NRP deliberately excluded: noisy and irrelevant for MSP documents.)
    "PERSON": ("PERSON", MEDIUM),
    "LOCATION": ("LOCATION", MEDIUM),
}

# NER post-filter: small spaCy models happily tag "Purge SSN" or "Backup NAS"
# as PERSON. Require name-shaped words before accepting an ML PERSON hit.
_NAME_WORD = re.compile(r"^[A-Z][a-z'’\-]+$")
_NAME_PARTICLES = {"van", "de", "der", "da", "la", "le", "von", "bin", "al",
                   "el", "mac", "st."}

# Title-case tech/business words that show up in headings and get NER-tagged
# as names ("Network Migration Runbook" → PERSON). Any hit disqualifies.
_PERSON_STOPWORDS = {
    "network", "migration", "runbook", "server", "backup", "restore",
    "switch", "firewall", "router", "gateway", "cutover", "weekend",
    "patch", "update", "upgrade", "storage", "cloud", "admin", "database",
    "windows", "linux", "report", "ticket", "invoice", "billing",
    "contact", "contacts", "management", "wireless", "subnet",
    "credentials", "reference", "environment", "current", "staged",
    "legacy", "warehouse", "manager", "escalation", "recovery",
    "controller", "bridge", "public", "private", "internal", "external",
    "office", "meeting", "notes", "summary", "policy", "change",
    "incident", "outage", "troubleshooting", "steps", "purge", "review",
}


def _plausible_person(text):
    words = text.split()
    if not 2 <= len(words) <= 4:
        return False  # single words come back via name-part propagation
    if any(w.lower() in _PERSON_STOPWORDS for w in words):
        return False
    return all(_NAME_WORD.match(w) or w.lower() in _NAME_PARTICLES
               for w in words)


def _has_acronym(text):
    return any(len(w) >= 2 and w.isupper() for w in text.split())
PRESIDIO_MIN_SCORE = 0.4


def _model_available(name):
    """importlib-based check — works in normal installs AND frozen (PyInstaller)
    bundles, where spacy.util.is_package can miss collected packages."""
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def resolve_nlp_model():
    """Best available spaCy model, largest first; blank pipeline as fallback.

    Returns (model_name_or_path, tier) where tier is 'full', 'small', or
    'patterns-only'. The blank fallback is generated once into a per-user
    cache dir, so the app works fully offline with no model installed.
    """
    import spacy

    for name, tier in (("en_core_web_lg", "full"),
                       ("en_core_web_md", "full"),
                       ("en_core_web_sm", "small")):
        if _model_available(name):
            return name, tier

    from pathlib import Path
    cache = Path.home() / ".docscrub" / "blank_en"
    if not (cache / "meta.json").exists():
        nlp = spacy.blank("en")
        nlp.add_pipe("sentencizer")
        cache.parent.mkdir(parents=True, exist_ok=True)
        nlp.to_disk(cache)
    return str(cache), "patterns-only"


def build_analyzer(model_name=None):
    """Presidio analyzer on the best available spaCy model.

    With a real model (en_core_web_lg/md/sm) Presidio also runs ML-based
    PERSON / LOCATION / ORG detection; with the blank fallback it is
    pattern recognizers only (the custom regex + heuristic layers still run).
    """
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    if model_name is None:
        model_name, _ = resolve_nlp_model()
    conf = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model_name}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=conf).create_engine()
    return AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])


# Analyzer is expensive to build (model load); share one per process.
# Token state lives on the Scrubber, so each document still gets a fresh map.
_SHARED = {}


def get_shared_analyzer():
    if "analyzer" not in _SHARED:
        name, tier = resolve_nlp_model()
        _SHARED.update(analyzer=build_analyzer(name), name=name, tier=tier)
    return _SHARED["analyzer"], _SHARED["name"], _SHARED["tier"]


class Scrubber:
    def __init__(self, model_name=None):
        if model_name:
            self.model_name, self.model_tier = model_name, "explicit"
            self.analyzer = build_analyzer(model_name)
        else:
            self.analyzer, self.model_name, self.model_tier = get_shared_analyzer()
        self.rules = [
            (name, etype, sev, prio, re.compile(pat, flags), group)
            for (name, etype, sev, prio, flags, group, pat) in REGEX_RULES
        ]
        # (entity_type, value) -> token ; consistent across the whole document
        self._token_map = {}
        self._type_counters = {}
        # name-part -> full value, so a later solo "Sarah" maps to the same
        # token as "Sarah Whitfield" (partial-leak prevention)
        self._name_parts = {}
        # values known to be sensitive from document STRUCTURE (email
        # display names, name-column cells) — redacted deterministically,
        # no model required
        self._known_values = {}

    def add_known_value(self, entity_type, value):
        """Register a value that document structure proves is sensitive
        (e.g. the display name in a From: header). Detected everywhere in
        subsequent text with high priority, and its parts propagate like
        any PERSON/ORG name."""
        value = " ".join(value.split())
        if len(value) < 3:
            return
        self._known_values.setdefault(value, entity_type)
        if entity_type in ("PERSON", "ORG"):
            for part in value.split():
                if (len(part) >= 3 and part[0].isupper()
                        and part.lower() not in _PERSON_STOPWORDS):
                    self._name_parts.setdefault(part, (entity_type, value))

    # ---------------- detection ----------------

    def detect(self, text):
        findings = []
        findings += self._detect_regex(text)
        findings += self._detect_presidio(text)
        findings += self._detect_names(text)
        findings += self._detect_known_values(text)
        findings = self._resolve_overlaps(findings)
        self._absorb_name_suffixes(text, findings)
        findings = self._propagate_name_parts(text, findings)
        return findings

    def _detect_known_values(self, text):
        """Exact-match structurally-known values AND their name parts.

        High priority: a display name from a From: header (or a bare
        "Marcus" from that name) beats a small-model LOCATION mislabel —
        parts must be detected PRE-resolution to displace NER noise."""
        out = []
        for value, etype in self._known_values.items():
            for m in re.finditer(r"(?<!\w)" + re.escape(value) + r"(?!\w)",
                                 text):
                out.append(Finding(
                    entity_type=etype, start=m.start(), end=m.end(),
                    text=value, score=0.9, severity=MEDIUM, layer="known",
                    priority=6, context=_context(text, m.start(), m.end()),
                ))
        for part, (etype, full_value) in self._name_parts.items():
            if part in self._known_values:
                continue  # already handled above
            for m in re.finditer(r"(?<!\w)" + re.escape(part) + r"(?!\w)",
                                 text):
                out.append(Finding(
                    entity_type=etype, start=m.start(), end=m.end(),
                    text=full_value,  # same token as the full name
                    score=0.85, severity=MEDIUM, layer="known", priority=5,
                    context=_context(text, m.start(), m.end()),
                ))
        return out

    @staticmethod
    def _absorb_name_suffixes(text, findings):
        """Extend PERSON spans over generational suffixes ("… Carter Jr.")."""
        for f in findings:
            if f.entity_type != "PERSON":
                continue
            m = re.match(r",?\s(?:Jr|Sr|II|III|IV)\b\.?", text[f.end:f.end + 6])
            if m:
                f.end += m.end()
                f.text = text[f.start:f.end]

    def _propagate_name_parts(self, text, findings):
        """Redact solo recurrences of already-detected person/org names.

        Once "Sarah Whitfield" is detected anywhere in the document, a later
        bare "Sarah" or "Whitfield" is also redacted, to the SAME token.
        """
        for f in findings:
            if f.entity_type in ("PERSON", "ORG"):
                for part in f.text.split():
                    if (len(part) >= 3 and part[0].isupper()
                            and part.lower() not in _PERSON_STOPWORDS):
                        self._name_parts.setdefault(part, (f.entity_type, f.text))
        extra = []
        for part, (etype, full_value) in self._name_parts.items():
            for m in re.finditer(r"\b" + re.escape(part) + r"\b", text):
                covered = any(m.start() < a.end and a.start < m.end()
                              for a in findings + extra)
                if not covered:
                    extra.append(Finding(
                        entity_type=etype, start=m.start(), end=m.end(),
                        text=full_value,  # map to the full value's token
                        score=0.6, severity=MEDIUM, layer="propagation",
                        priority=2,
                        context=_context(text, m.start(), m.end()),
                    ))
        if extra:
            findings = sorted(findings + extra, key=lambda f: f.start)
        return findings

    def _detect_regex(self, text):
        out = []
        for (name, etype, sev, prio, rx, group) in self.rules:
            for m in rx.finditer(text):
                start, end = m.span(group)
                value = m.group(group)
                final_type, final_sev = etype, sev
                if etype == "IP_ADDRESS":
                    final_type, final_sev = self._classify_ip(value)
                    if final_type is None:
                        continue
                elif etype == "POSSIBLE_SECRET" and not _looks_like_secret(value):
                    continue
                out.append(Finding(
                    entity_type=final_type, start=start, end=end, text=value,
                    score=0.95, severity=final_sev, layer="regex",
                    priority=prio, context=_context(text, start, end),
                ))
        return out

    @staticmethod
    def _classify_ip(value):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return None, None
        if (ip.is_loopback or ip.is_unspecified or ip.is_multicast
                or ip.is_reserved):
            # 127.0.0.1 / 0.0.0.0 / 224.x / 255.255.255.0-style netmasks
            return None, None
        if ip.is_private or ip.is_link_local:
            return "INTERNAL_IP", HIGH
        return "PUBLIC_IP", HIGH

    def _detect_presidio(self, text):
        out = []
        results = self.analyzer.analyze(text=text, language="en")
        for r in results:
            if r.entity_type not in PRESIDIO_KEEP or r.score < PRESIDIO_MIN_SCORE:
                continue
            value = text[r.start:r.end]
            try:  # IP-shaped text is the regex layer's job; Presidio's
                ipaddress.ip_address(value.strip())   # PHONE recognizer loves
                continue                              # to grab netmasks
            except ValueError:
                pass
            if r.entity_type == "PERSON" and not _plausible_person(value):
                continue
            if r.entity_type == "LOCATION" and (_has_acronym(value)
                                                or any(c.isdigit() for c in value)):
                continue
            etype, sev = PRESIDIO_KEEP[r.entity_type]
            out.append(Finding(
                entity_type=etype, start=r.start, end=r.end,
                text=text[r.start:r.end], score=r.score, severity=sev,
                layer="presidio", priority=4,
                context=_context(text, r.start, r.end),
            ))
        return out

    def _detect_names(self, text):
        out = []
        for rx, etype in ((NAME_HEURISTIC, "PERSON"), (ORG_HEURISTIC, "ORG")):
            for m in rx.finditer(text):
                start, end = m.span(1)
                out.append(Finding(
                    entity_type=etype, start=start, end=end, text=m.group(1),
                    score=0.65, severity=MEDIUM, layer="heuristic", priority=3,
                    context=_context(text, start, end),
                ))
        for m in ORG_SUFFIX.finditer(text):
            value = m.group(1)
            prefix_words = value.split()[:-1]
            if any(w.lower() in ORG_STOPWORDS for w in prefix_words):
                continue
            out.append(Finding(
                entity_type="ORG", start=m.start(1), end=m.end(1), text=value,
                score=0.7, severity=MEDIUM, layer="heuristic", priority=3,
                context=_context(text, m.start(1), m.end(1)),
            ))
        return out

    @staticmethod
    def _resolve_overlaps(findings):
        """Keep the best finding when spans overlap: priority, then length, then score."""
        findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
        accepted = []
        for f in findings:
            clash = None
            for a in accepted:
                if f.start < a.end and a.start < f.end:
                    clash = a
                    break
            if clash is None:
                accepted.append(f)
            else:
                better = (f.priority, f.end - f.start, f.score) > \
                         (clash.priority, clash.end - clash.start, clash.score)
                if better:
                    accepted.remove(clash)
                    accepted.append(f)
        accepted.sort(key=lambda f: f.start)
        return accepted

    # ---------------- tokenization ----------------

    def _token_for(self, finding):
        key = (finding.entity_type, finding.text)
        if key not in self._token_map:
            n = self._type_counters.get(finding.entity_type, 0) + 1
            self._type_counters[finding.entity_type] = n
            self._token_map[key] = f"<{finding.entity_type}_{n}>"
        return self._token_map[key]

    def sanitize_text(self, text):
        """Returns (sanitized_text, findings). Same value → same token everywhere."""
        findings = self.detect(text)
        for f in findings:
            f.token = self._token_for(f)
        out, cursor = [], 0
        for f in findings:
            out.append(text[cursor:f.start])
            out.append(f.token)
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out), findings

    # ---------------- mapping ----------------

    def mapping(self):
        return {
            token: {"type": etype, "value": value}
            for (etype, value), token in self._token_map.items()
        }

    def save_mapping(self, path):
        with open(path, "w") as fh:
            json.dump(self.mapping(), fh, indent=2)


def rehydrate(text, mapping):
    """Replace tokens in AI output with original values (longest token first)."""
    for token in sorted(mapping, key=len, reverse=True):
        text = text.replace(token, mapping[token]["value"])
    return text


def _context(text, start, end, radius=30):
    a, b = max(0, start - radius), min(len(text), end + radius)
    snippet = text[a:b].replace("\n", " ")
    return ("…" if a > 0 else "") + snippet + ("…" if b < len(text) else "")
