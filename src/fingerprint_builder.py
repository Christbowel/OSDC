import json
import re
import sys
from pathlib import Path


EXPERT_FINGERPRINTS = {
    "CWE-79": {
        "name": "XSS",
        "add_tokens": ["htmlspecialchars", "escape", "sanitize", "encode", "textcontent", "innertext", "dompurify", "bleach", "markupsafe", "xss", "encodeuri", "encodeuricomponent", "createtextnode", "safe", "escapehtml", "noescape"],
        "del_tokens": ["innerhtml", "document.write", "dangerouslysetinnerhtml", "v-html", "outerhtml", "writeln", "unescape"],
    },
    "CWE-89": {
        "name": "SQL_INJECTION",
        "add_tokens": ["parameterized", "placeholder", "prepare", "prepared", "bindparam", "bindvalue", "sqlparameter", "sanitize", "escape", "quote", "args", "params"],
        "del_tokens": ["format", "sprintf", "concat", "interpolat", "f-string", "execute", "raw", "query"],
    },
    "CWE-78": {
        "name": "COMMAND_INJECTION",
        "add_tokens": ["execfile", "execfilesync", "subprocess.run", "shlex.quote", "shellescape", "escapeshellarg", "allowlist", "safelist", "validate", "sanitize"],
        "del_tokens": ["exec", "eval", "system", "popen", "execsync", "child_process", "shell", "os.system", "passthru", "proc_open"],
    },
    "CWE-22": {
        "name": "PATH_TRAVERSAL",
        "add_tokens": ["realpath", "filepath.clean", "path.normalize", "abspath", "startswith", "resolve", "basename", "sanitize", "canonicalize", "chroot", "safejoin"],
        "del_tokens": ["path.join", "filepath.join", "os.path.join", "open", "readfile", "writefile", "extract", "mkdir", "unlink"],
    },
    "CWE-352": {
        "name": "CSRF",
        "add_tokens": ["csrf", "xsrf", "csrftoken", "csrfmiddleware", "antiforgery", "samesite", "strict", "token", "verify", "validate"],
        "del_tokens": ["nocsrf", "skip", "disable", "exempt"],
    },
    "CWE-287": {
        "name": "AUTH_BYPASS",
        "add_tokens": ["authenticate", "authorize", "verify", "validate", "checkpermission", "isauthorized", "requireauth", "guard", "middleware", "interceptor"],
        "del_tokens": ["skip", "bypass", "noauth", "public", "anonymous", "allowanonymous"],
    },
    "CWE-918": {
        "name": "SSRF",
        "add_tokens": ["allowlist", "whitelist", "validateurl", "isprivateip", "isinternal", "blocklist", "denylist", "safelist", "resolvehost", "pinned"],
        "del_tokens": ["fetch", "request", "urlopen", "httpget", "curl", "redirect"],
    },
    "CWE-601": {
        "name": "OPEN_REDIRECT",
        "add_tokens": ["validateredirect", "isrelativeurl", "safeurl", "allowedhost", "samorigin", "sanitizepathname", "isredirect"],
        "del_tokens": ["redirect", "location", "header", "sendredirect", "moved"],
    },
    "CWE-502": {
        "name": "DESERIALIZATION",
        "add_tokens": ["safe_load", "weights_only", "allowlist", "whitelist", "json.loads", "defusedxml", "safeloader", "restricted"],
        "del_tokens": ["pickle.load", "yaml.load", "torch.load", "unserialize", "marshal.load", "objectinputstream", "readobject", "deserialize"],
    },
    "CWE-327": {
        "name": "WEAK_CRYPTO",
        "add_tokens": ["sha256", "sha384", "sha512", "bcrypt", "argon2", "scrypt", "aes256", "chacha20", "ed25519", "pbkdf2"],
        "del_tokens": ["md5", "sha1", "des", "rc4", "blowfish", "ecb", "cbc"],
    },
    "CWE-330": {
        "name": "WEAK_RANDOM",
        "add_tokens": ["secrets", "crypto.randombytes", "securerandom", "csprng", "getrandom", "urandom", "randombytes"],
        "del_tokens": ["math.random", "random.random", "rand", "srand", "mt_rand"],
    },
    "CWE-362": {
        "name": "RACE_CONDITION",
        "add_tokens": ["lock", "mutex", "synchronized", "atomic", "semaphore", "rwlock", "compare_and_swap", "flock"],
        "del_tokens": ["unlock", "unsynchronized", "volatile"],
    },
    "CWE-400": {
        "name": "RESOURCE_EXHAUSTION",
        "add_tokens": ["ratelimit", "throttle", "maxsize", "maxlength", "limit", "timeout", "maxdepth", "maxiteration", "bounded", "capacity"],
        "del_tokens": ["unlimited", "nolimit", "infinite"],
    },
    "CWE-611": {
        "name": "XXE",
        "add_tokens": ["defusedxml", "disallow_dtd", "disallow_entities", "feature_external", "noentityresolver", "safe", "xmlparsertype"],
        "del_tokens": ["parsestring", "parse", "xmlparser", "saxparser", "documentbuilder", "loadxml"],
    },
    "CWE-190": {
        "name": "INTEGER_OVERFLOW",
        "add_tokens": ["checkedadd", "checkedmul", "safemath", "overflow", "max_value", "bounds", "saturating", "wrapping"],
        "del_tokens": ["cast", "convert", "truncate"],
    },
    "CWE-416": {
        "name": "USE_AFTER_FREE",
        "add_tokens": ["ref_count", "addref", "prevent", "guard", "prevent_free", "prevent_release"],
        "del_tokens": ["free", "release", "delete", "destroy", "dealloc", "kfree"],
    },
    "CWE-476": {
        "name": "NULL_DEREF",
        "add_tokens": ["nullcheck", "nil", "optional", "guard", "len", "isempty", "notnull", "requirenonnull"],
        "del_tokens": ["deref", "access", "field", "method"],
    },
    "CWE-862": {
        "name": "MISSING_AUTHZ",
        "add_tokens": ["checkpermission", "authorize", "hasaccess", "canaccess", "ispermitted", "overrideaccess", "accesscontrol", "acl"],
        "del_tokens": ["public", "open", "unrestricted"],
    },
    "CWE-798": {
        "name": "HARDCODED_CREDENTIALS",
        "add_tokens": ["environ", "env", "config", "vault", "secret_manager", "getenv", "keychain"],
        "del_tokens": ["password", "secret", "apikey", "token", "credential", "hardcoded"],
    },
    "CWE-1321": {
        "name": "PROTOTYPE_POLLUTION",
        "add_tokens": ["hasownproperty", "object.create", "freeze", "seal", "preventextensions", "safeset", "parent", "key"],
        "del_tokens": ["__proto__", "constructor", "prototype", "assign", "merge", "extend", "set"],
    },
    "CWE-200": {
        "name": "INFO_DISCLOSURE",
        "add_tokens": ["redact", "mask", "sanitize", "generic", "opaque", "stripped"],
        "del_tokens": ["stacktrace", "traceback", "debug", "verbose", "dump", "printr", "var_dump", "console.log"],
    },
    "CWE-347": {
        "name": "MISSING_SIGNATURE_CHECK",
        "add_tokens": ["verify", "validate", "checksignature", "hmac", "compare_digest", "timingsafeequal", "hash_equals"],
        "del_tokens": ["skip", "trust", "nosignature", "unverified"],
    },
    "CWE-434": {
        "name": "UNRESTRICTED_UPLOAD",
        "add_tokens": ["allowedextensions", "mimetype", "contenttype", "validate", "whitelist", "maxsize", "sanitizefilename"],
        "del_tokens": ["upload", "save", "write", "movefile", "putobject"],
    },
    "CWE-94": {
        "name": "CODE_INJECTION",
        "add_tokens": ["sandbox", "safeval", "restricted", "allowlist", "validate", "ast.literal_eval"],
        "del_tokens": ["eval", "exec", "compile", "function", "settimeout", "setinterval"],
    },
    "CWE-295": {
        "name": "IMPROPER_CERT_VALIDATION",
        "add_tokens": ["verify", "verifypeer", "checkhostname", "pinnedcert", "trustmanager", "ssl_verify"],
        "del_tokens": ["insecure", "noverify", "verify_none", "disable", "trustall", "allowall"],
    },
    "CWE-1333": {
        "name": "REDOS",
        "add_tokens": ["safe-regex", "saferegex", "lastindex", "reset", "timeout", "maxlength", "bounded"],
        "del_tokens": ["regexp", "regex", "test", "match", "exec"],
    },
    "CWE-269": {
        "name": "PRIVILEGE_ESCALATION",
        "add_tokens": ["checkrole", "requirerole", "permission", "droprights", "setuid", "validate"],
        "del_tokens": ["admin", "root", "superuser", "elevate", "grant"],
    },
    "CWE-770": {
        "name": "RESOURCE_ALLOCATION",
        "add_tokens": ["maxentries", "limit", "cap", "bounded", "pool", "quota", "maxmembers"],
        "del_tokens": ["unlimited", "append", "push", "add", "grow"],
    },
}


def extract_tokens(line: str) -> set:
    tokens = set()
    identifiers = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*', line)
    for ident in identifiers:
        tokens.add(ident.lower())
        parts = ident.split(".")
        for part in parts:
            tokens.add(part.lower())
    return tokens


def parse_diff(diff_code: str) -> tuple[set, set]:
    add_tokens = set()
    del_tokens = set()
    for line in diff_code.splitlines():
        stripped = line.strip()
        if stripped.startswith("+") and not stripped.startswith("+++"):
            add_tokens.update(extract_tokens(stripped[1:]))
        elif stripped.startswith("-") and not stripped.startswith("---"):
            del_tokens.update(extract_tokens(stripped[1:]))
    return add_tokens, del_tokens


def build_fingerprints(output_path: str = "data/fingerprints.json"):
    print("=== OSDC Fingerprint Builder ===")

    fingerprints = {}

    print(f"Loading {len(EXPERT_FINGERPRINTS)} expert-curated CWE fingerprints...")
    for cwe_id, fp in EXPERT_FINGERPRINTS.items():
        fingerprints[cwe_id] = {
            "name": fp["name"],
            "add_tokens": fp["add_tokens"],
            "del_tokens": fp["del_tokens"],
            "sample_count": 100,
        }

    osdc_jsonl = Path("data/patterns.jsonl")
    if osdc_jsonl.exists():
        print("Enriching with OSDC live data...")
        osdc_count = 0
        with open(osdc_jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if record.get("_type") != "advisory":
                    continue

                key_diff = record.get("key_diff", "")
                pattern_id = record.get("pattern_id", "")
                if not pattern_id or not key_diff:
                    continue

                add_tokens, del_tokens = parse_diff(key_diff)

                noise = {"the", "a", "is", "are", "return", "def", "function", "if", "else", "for", "while", "this", "self", "var", "let", "const", "err", "error", "nil", "null", "none", "true", "false", "new", "import"}
                add_tokens -= noise
                del_tokens -= noise
                add_tokens = {t for t in add_tokens if len(t) > 2}
                del_tokens = {t for t in del_tokens if len(t) > 2}

                osdc_key = f"OSDC:{pattern_id}"
                if osdc_key not in fingerprints:
                    fingerprints[osdc_key] = {
                        "name": pattern_id,
                        "add_tokens": [],
                        "del_tokens": [],
                        "sample_count": 0,
                    }

                fp = fingerprints[osdc_key]
                fp["sample_count"] += 1
                for t in add_tokens:
                    if t not in fp["add_tokens"]:
                        fp["add_tokens"].append(t)
                for t in del_tokens:
                    if t not in fp["del_tokens"]:
                        fp["del_tokens"].append(t)

                osdc_count += 1

        print(f"  Processed {osdc_count} OSDC advisories")
        print(f"  Added {len([k for k in fingerprints if k.startswith('OSDC:')])} OSDC patterns")
    else:
        print("No OSDC data found (data/patterns.jsonl missing)")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(fingerprints, f, indent=2, ensure_ascii=False)

    print(f"\nFingerprints saved to {output_path}")
    print(f"Total patterns: {len(fingerprints)}")
    print(f"  Expert CWE: {len(EXPERT_FINGERPRINTS)}")
    print(f"  OSDC live: {len([k for k in fingerprints if k.startswith('OSDC:')])}")

    print("\nTop patterns by token count:")
    top = sorted(fingerprints.items(), key=lambda x: len(x[1]["add_tokens"]) + len(x[1]["del_tokens"]), reverse=True)[:10]
    for pid, data in top:
        total = len(data["add_tokens"]) + len(data["del_tokens"])
        print(f"  {pid} ({data['name']}): {total} tokens, {data['sample_count']} samples")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "data/fingerprints.json"
    build_fingerprints(output)