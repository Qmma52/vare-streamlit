"""
Prompt-injection detector + client<->server gateway.

Pipeline:  normalise -> decode hidden payloads -> rule matching -> risk score -> decision
Gateway :  inspects every string field of the client's JSON request, blocks/sanitises,
           forwards to server, then inspects the server's response for leaks.
"""
import base64
import json
import re
import unicodedata
import urllib.parse

F = re.I | re.S | re.M

# (id, category, regex, weight, description)
RULES = [
    ("PI-001", "Instruction override",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|system)\b.{0,30}\b(instructions?|prompts?|rules?|guidelines?|directives?|constraints?)\b",
     0.85, "Attempt to override previous/system instructions"),
    ("PI-002", "Role hijack",
     r"\b(you are now|from now on,? you are|pretend (to be|you are)|roleplay as|act as (if you are )?(an? )?(unrestricted|root|admin|hacker))\b",
     0.55, "Attempt to change the model's role/persona"),
    ("PI-003", "Jailbreak persona",
     r"\b(DAN|do anything now|developer mode|jailbreak|god mode|unfiltered mode)\b",
     0.80, "Known jailbreak persona / mode"),
    ("PI-004", "System prompt exfiltration",
     r"\b(reveal|show|print|repeat|output|display|leak|tell me)\b.{0,40}\b(system|hidden|initial|original|secret)\b.{0,20}\b(prompt|instructions?|message|rules)\b",
     0.85, "Attempt to extract the hidden system prompt"),
    ("PI-005", "Delimiter / role-tag injection",
     r"(</?\s*(system|assistant|instructions?)\s*>|\[/?INST\]|<\|im_(start|end)\|>|^#{2,}\s*(system|instructions?)\b|\bBEGIN (SYSTEM|NEW) (PROMPT|INSTRUCTIONS)\b)",
     0.75, "Context spoofing via fake system/assistant delimiters"),
    ("PI-006", "Secret extraction",
     r"(\b(api[_ -]?key|password|secret|token|credentials?|private key)\b.{0,30}\b(show|reveal|send|give|print|output|leak)\b|\b(show|reveal|send|give|print|output|leak)\b.{0,30}\b(api[_ -]?key|password|secret|token|credentials?|private key)\b)",
     0.60, "Requesting credentials / secrets"),
    ("PI-007", "Tool / command abuse",
     r"(\b(execute|run|eval)\b.{0,30}\b(command|shell|bash|powershell|code|script|sql)\b|;\s*(drop|delete)\s+table|\brm\s+-rf\b|\b(curl|wget)\s+https?://)",
     0.70, "Attempt to execute shell/SQL/tool commands"),
    ("PI-008", "Data exfiltration channel",
     r"(!\[[^\]]*\]\(https?://[^)]*\?[^)]*=|\b(send|forward|post|email|exfiltrate)\b.{0,50}\b(https?://\S+|\S+@\S+\.\S+))",
     0.75, "Channel for sending data to an external URL/email"),
    ("PI-009", "Indirect injection (hidden in content)",
     r"(<!--.{0,200}?(ignore|instruction|assistant|\bAI\b).{0,200}?-->|\b(if you are (an? )?(ai|llm|assistant|language model)|note to (the )?(ai|assistant|model)|attention (ai|assistant|llm))\b)",
     0.70, "AI-targeted instruction hidden in document/web content"),
    ("PI-010", "Safety bypass",
     r"\b(without (any )?(restrictions?|limitations?|filters?|censorship)|no (ethical|safety) (guidelines|restrictions)|disable (your )?(safety|filters?|guardrails?))\b",
     0.60, "Demand to remove safety guardrails"),
    ("PI-011", "Authority / urgency claim",
     r"\b(this is (an )?(official|urgent|admin|system) (message|override|command)|i am (the )?(admin|developer|administrator|owner|your creator))\b",
     0.50, "Pressuring compliance through fake authority"),
]
COMPILED = [(i, c, re.compile(p, F), w, d) for i, c, p, w, d in RULES]

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
                            "х": "x", "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g"})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

BLOCK_T, FLAG_T = 0.70, 0.40


def normalize(text):
    """Return (views, obfuscation_flags). views = list of (label, text)."""
    flags = []
    t = unicodedata.normalize("NFKC", text)
    if ZERO_WIDTH.search(t):
        flags.append("zero-width characters")
        t = ZERO_WIDTH.sub("", t)
    t2 = t.translate(HOMOGLYPHS)
    if t2 != t:
        flags.append("unicode homoglyphs")
        t = t2
    if re.search(r"%[0-9a-fA-F]{2}", t):
        d = urllib.parse.unquote(t)
        if d != t:
            flags.append("URL-encoding")
            t = d
    views = [("plain", t)]
    for m in B64.findall(t):
        try:
            dec = base64.b64decode(m + "=" * (-len(m) % 4), validate=False).decode("utf-8")
            if dec.isprintable() or "\n" in dec:
                flags.append("base64 payload")
                views.append(("base64-decoded", dec))
        except Exception:
            pass
    leet = t.translate(LEET)
    if leet != t:
        views.append(("leet-normalised", leet))
    return views, sorted(set(flags))


def scan(text):
    views, flags = normalize(text or "")
    matches, seen = [], set()
    for label, view in views:
        for rid, cat, rx, w, desc in COMPILED:
            m = rx.search(view)
            if m and (rid, label) not in seen:
                seen.add((rid, label))
                matches.append({"rule": rid, "category": cat, "weight": w, "view": label,
                                "snippet": m.group(0)[:90], "description": desc})
    keep = {}
    for m in matches:                       # dedupe rule across views (keep highest)
        if m["rule"] not in keep or m["weight"] > keep[m["rule"]]["weight"]:
            keep[m["rule"]] = m
    matches = list(keep.values())
    p = 1.0
    for m in matches:
        p *= (1 - m["weight"])
    score = 1 - p
    if matches and flags:
        score = min(0.99, score + 0.15)          # obfuscation bonus
    decision = "BLOCK" if score >= BLOCK_T else "FLAG" if score >= FLAG_T else "ALLOW"
    return {"decision": decision, "risk": round(score, 2), "matches": matches,
            "obfuscation": flags, "sanitized": sanitize(views[0][1])}


def sanitize(text):
    for _, _, rx, _, _ in COMPILED:
        text = rx.sub("[removed]", text)
    return text


# ---------------- output (server -> client) leak detection ----------------
OUTPUT_RULES = [
    ("OUT-001", "API key leaked", re.compile(r"\b(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b")),
    ("OUT-002", "System prompt leaked", re.compile(r"\b(system prompt|my instructions (are|say))\s*[:\-]", re.I)),
    ("OUT-003", "Private key leaked", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("OUT-004", "Password in output", re.compile(r"\b(password|passwd|pwd)\s*[=:]\s*\S+", re.I)),
]


def scan_response(text):
    hits = [{"rule": r, "category": c, "snippet": m.group(0)[:60]}
            for r, c, rx in OUTPUT_RULES for m in [rx.search(text or "")] if m]
    red = text or ""
    for _, _, rx in OUTPUT_RULES:
        red = rx.sub("[REDACTED]", red)
    return {"leak": bool(hits), "hits": hits, "redacted": red}


def _walk(obj, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _apply(obj, fn):
    if isinstance(obj, dict):
        return {k: _apply(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_apply(v, fn) for v in obj]
    return fn(obj) if isinstance(obj, str) else obj


def vulnerable_demo_server(payload):
    """Intentionally naive LLM-app backend used to demonstrate the attack."""
    msg = json.dumps(payload).lower()
    if re.search(r"ignore|system prompt|instructions", msg):
        return ("System prompt: You are BankBot. Internal API_KEY sk-DEMO1234567890abcdefgh. "
                "password=admin@123")
    return f"BankBot: I'm happy to help. (received {len(msg)} bytes)"


class Gateway:
    """Security gateway placed between client and server."""

    def __init__(self, enabled=True):
        self.enabled = enabled

    def handle(self, payload, server_fn=vulnerable_demo_server):
        trace = {"gateway": self.enabled, "request_findings": [], "decision": "ALLOW",
                 "forwarded": payload, "response_raw": None, "response_final": None,
                 "response_leak": None}
        if self.enabled:
            worst = 0.0
            for path, val in _walk(payload):
                r = scan(val)
                if r["matches"]:
                    trace["request_findings"].append({"field": path, **{k: r[k] for k in
                                                      ("decision", "risk", "obfuscation")},
                                                      "rules": [m["rule"] + " " + m["category"] for m in r["matches"]]})
                worst = max(worst, r["risk"])
            trace["decision"] = "BLOCK" if worst >= BLOCK_T else "FLAG" if worst >= FLAG_T else "ALLOW"
            if trace["decision"] == "BLOCK":
                trace["response_final"] = "Request blocked by the gateway (prompt injection detected)."
                return trace
            if trace["decision"] == "FLAG":
                trace["forwarded"] = _apply(payload, lambda s: scan(s)["sanitized"])
        raw = server_fn(trace["forwarded"])
        trace["response_raw"] = raw
        if self.enabled:
            out = scan_response(raw)
            trace["response_leak"] = out
            trace["response_final"] = out["redacted"]
        else:
            trace["response_final"] = raw
        return trace
