import json
import re
import sys
from pathlib import Path
from collections import defaultdict

EXPERT_FINGERPRINTS = {
    "CWE-79": {
        "name": "XSS",
        "add_tokens": ["htmlspecialchars", "escape", "sanitize", "encode", "textcontent", "innertext", "dompurify", "bleach", "markupsafe", "xss", "encodeuri", "encodeuricomponent", "createtextnode", "safe", "escapehtml", "noescape", "htmlentities", "filter_var", "strip_tags"],
        "del_tokens": ["innerhtml", "document.write", "dangerouslysetinnerhtml", "v-html", "outerhtml", "writeln", "unescape"],
    },
    "CWE-89": {
        "name": "SQL_INJECTION",
        "add_tokens": ["parameterized", "placeholder", "prepare", "prepared", "bindparam", "bindvalue", "sqlparameter", "sanitize", "escape", "quote", "args", "params", "preparedstatement", "pdo", "mysqli_prepare"],
        "del_tokens": ["format", "sprintf", "concat", "interpolat", "f-string", "execute", "raw", "query", "string.format"],
    },
    "CWE-78": {
        "name": "COMMAND_INJECTION",
        "add_tokens": ["execfile", "execfilesync", "subprocess.run", "shlex.quote", "shellescape", "escapeshellarg", "allowlist", "safelist", "validate", "sanitize", "processbuilder", "subprocess.check_call"],
        "del_tokens": ["exec", "eval", "system", "popen", "execsync", "child_process", "shell", "os.system", "passthru", "proc_open", "pcntl_exec", "shell_exec", "runtime.exec", "os.popen", "commands.getoutput"],
    },
    "CWE-22": {
        "name": "PATH_TRAVERSAL",
        "add_tokens": ["realpath", "filepath.clean", "path.normalize", "abspath", "startswith", "resolve", "basename", "sanitize", "canonicalize", "chroot", "safejoin", "filepath.evalsymlinks", "filepath.abs"],
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
        "add_tokens": ["safe_load", "weights_only", "allowlist", "whitelist", "json.loads", "defusedxml", "safeloader", "restricted", "json_decode"],
        "del_tokens": ["pickle.load", "yaml.load", "torch.load", "unserialize", "marshal.load", "objectinputstream", "readobject", "deserialize", "cpickle", "xmldecoder"],
    },
    "CWE-327": {
        "name": "WEAK_CRYPTO",
        "add_tokens": ["sha256", "sha384", "sha512", "bcrypt", "argon2", "scrypt", "aes256", "chacha20", "ed25519", "pbkdf2", "password_hash", "password_verify"],
        "del_tokens": ["md5", "sha1", "des", "rc4", "blowfish", "ecb", "cbc"],
    },
    "CWE-330": {
        "name": "WEAK_RANDOM",
        "add_tokens": ["secrets", "crypto.randombytes", "securerandom", "csprng", "getrandom", "urandom", "randombytes", "random_bytes", "random_int", "os.urandom", "secrets.token"],
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
        "add_tokens": ["hasownproperty", "object.create", "freeze", "seal", "preventextensions", "safeset", "parent", "key", "structuredclone"],
        "del_tokens": ["__proto__", "constructor", "prototype", "assign", "merge", "extend", "set", "object.assign"],
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
        "del_tokens": ["eval", "exec", "compile", "function", "settimeout", "setinterval", "create_function", "assert", "call_user_func", "scriptengine"],
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
    "CWE-119": {
        "name": "BUFFER_OVERFLOW",
        "add_tokens": ["strncpy", "snprintf", "fgets", "strlcpy", "strlcat", "memcpy_s", "bounded"],
        "del_tokens": ["strcpy", "gets", "sprintf", "strcat", "scanf", "malloc"],
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

    patchdb_loaded = False
    try:
        from datasets import load_dataset
        print("Downloading PatchDB from Hugging Face...")
        ds = load_dataset("sunlab/patch_db", split="train")
        print(f"Loaded {len(ds)} samples")

        security_patches = [s for s in ds if s.get("category") == "security"]
        print(f"Security patches: {len(security_patches)}")

        cwe_tokens = defaultdict(lambda: {"add": defaultdict(int), "del": defaultdict(int), "count": 0})

        noise = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "have", "has", "had", "do", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "shall",
            "if", "else", "elif", "then", "for", "while", "in", "not",
            "and", "or", "but", "with", "from", "to", "of", "at", "by",
            "return", "def", "function", "class", "var", "let", "const",
            "int", "string", "bool", "void", "null", "none", "true", "false",
            "this", "self", "new", "import", "from", "export", "module",
            "public", "private", "protected", "static", "final",
            "try", "catch", "except", "finally", "throw", "raise",
            "err", "error", "fmt", "log", "print", "printf",
        }

        for i, sample in enumerate(security_patches):
            cwe_id = sample.get("CWE_ID", "NA")
            diff_code = sample.get("diff_code", "")

            if not diff_code or cwe_id == "NA":
                continue

            add_t, del_t = parse_diff(diff_code)
            add_t -= noise
            del_t -= noise
            add_t = {t for t in add_t if len(t) > 2}
            del_t = {t for t in del_t if len(t) > 2}

            entry = cwe_tokens[cwe_id]
            entry["count"] += 1
            for token in add_t:
                entry["add"][token] += 1
            for token in del_t:
                entry["del"][token] += 1

            if (i + 1) % 2000 == 0:
                print(f"  Processed {i + 1}/{len(security_patches)}")

        print(f"Building PatchDB fingerprints for {len(cwe_tokens)} CWE categories...")

        for cwe_id, data in cwe_tokens.items():
            if data["count"] < 3:
                continue

            min_freq = max(2, data["count"] // 10)

            top_add = sorted(
                [(t, c) for t, c in data["add"].items() if c >= min_freq],
                key=lambda x: x[1], reverse=True
            )[:50]

            top_del = sorted(
                [(t, c) for t, c in data["del"].items() if c >= min_freq],
                key=lambda x: x[1], reverse=True
            )[:50]

            if not top_add and not top_del:
                continue

            pdb_key = f"PDB:{cwe_id}"
            existing = fingerprints.get(cwe_id, {})

            if pdb_key not in fingerprints:
                fingerprints[pdb_key] = {
                    "name": existing.get("name", cwe_id),
                    "add_tokens": [t for t, _ in top_add],
                    "del_tokens": [t for t, _ in top_del],
                    "sample_count": data["count"],
                }
            else:
                fp = fingerprints[pdb_key]
                for t, _ in top_add:
                    if t not in fp["add_tokens"]:
                        fp["add_tokens"].append(t)
                for t, _ in top_del:
                    if t not in fp["del_tokens"]:
                        fp["del_tokens"].append(t)
                fp["sample_count"] += data["count"]

        patchdb_loaded = True
        print(f"  PatchDB patterns added: {len([k for k in fingerprints if k.startswith('PDB:')])}")

    except ImportError:
        print("PatchDB not available (install: pip install datasets)")
        print("Using expert fingerprints only")
    except Exception as exc:
        print(f"PatchDB loading failed: {exc}")
        print("Using expert fingerprints only")

    osdc_jsonl = Path("data/patterns.jsonl")
    if osdc_jsonl.exists():
        print("Enriching with OSDC live data...")
        osdc_count = 0
        with open(osdc_jsonl) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("_type") != "advisory":
                    continue

                key_diff = record.get("key_diff", "")
                pattern_id = record.get("pattern_id", "")
                if not pattern_id or not key_diff or pattern_id == "UNCLASSIFIED":
                    continue

                add_t, del_t = parse_diff(key_diff)
                noise_small = {"the", "a", "is", "are", "return", "def", "function", "if", "else", "for", "while", "this", "self", "var", "let", "const", "err", "error", "nil", "null", "none", "true", "false", "new", "import"}
                add_t -= noise_small
                del_t -= noise_small
                add_t = {t for t in add_t if len(t) > 2}
                del_t = {t for t in del_t if len(t) > 2}

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
                for t in add_t:
                    if t not in fp["add_tokens"]:
                        fp["add_tokens"].append(t)
                for t in del_t:
                    if t not in fp["del_tokens"]:
                        fp["del_tokens"].append(t)

                osdc_count += 1

        print(f"  Processed {osdc_count} OSDC advisories")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(fingerprints, f, indent=2, ensure_ascii=False)

    expert_count = len(EXPERT_FINGERPRINTS)
    pdb_count = len([k for k in fingerprints if k.startswith("PDB:")])
    osdc_count = len([k for k in fingerprints if k.startswith("OSDC:")])

    print(f"\nFingerprints saved to {output_path}")
    print(f"Total patterns: {len(fingerprints)}")
    print(f"  Expert CWE: {expert_count}")
    if patchdb_loaded:
        print(f"  PatchDB: {pdb_count}")
    print(f"  OSDC live: {osdc_count}")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "data/fingerprints.json"
    build_fingerprints(output)
