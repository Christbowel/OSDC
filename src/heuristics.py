import re
from functools import lru_cache


@lru_cache(maxsize=512)
def _compiled(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


def _search(pattern: str, text: str, flags: int = 0):
    return _compiled(pattern, flags).search(text)

SECURITY_FILE_PATTERNS_HIGH = [
    (r"auth[._/]", 5),
    (r"login[._/]", 5),
    (r"session[._/]", 4),
    (r"password[._/]", 5),
    (r"credential", 5),
    (r"crypto[._/]", 5),
    (r"cipher", 4),
    (r"encrypt", 4),
    (r"hmac[._/]", 5),
    (r"permission[._/]", 4),
    (r"privilege", 4),
    (r"acl[._/]", 4),
    (r"sanitiz", 4),
    (r"security[._/]", 4),
    (r"csrf", 5),
    (r"xss", 5),
    (r"cors[._/]", 3),
    (r"token[._/]", 3),
    (r"oauth", 4),
    (r"jwt[._/]", 4),
    (r"saml", 4),
    (r"cert[._/]", 3),
    (r"tls[._/]", 3),
    (r"ssl[._/]", 3),
    (r"config[._/]", 3),
    (r"\.env", 5),
    (r"secrets?[._/]", 5),
    (r"private[._/]", 4),
    (r"\.htaccess", 5),
    (r"web\.config", 4),
    (r"nginx\.conf", 3),
    (r"apache\.conf", 3),
    (r"application\.(properties|yml)", 3),
    (r"settings\.py", 3),
    (r"wp-config\.php", 5),
]

SECURITY_FILE_PATTERNS_LOW = [
    (r"validat", 2),
    (r"escap", 2),
    (r"filter[._/]", 2),
    (r"middleware[._/]", 2),
    (r"intercept", 2),
    (r"guard[._/]", 2),
    (r"policy[._/]", 2),
    (r"webhook[._/]", 2),
    (r"upload[._/]", 2),
    (r"redirect", 2),
    (r"cookie[._/]", 2),
    (r"header[._/]", 1),
    (r"endpoint[._/]", 1),
    (r"handler[._/]", 1),
    (r"parser[._/]", 1),
    (r"deserializ", 3),
    (r"unmarshal", 3),
]

SKIP_FILE_PATTERNS = [
    r"test[_/]", r"_test\.", r"\.test\.", r"spec[_/]", r"__tests__",
    r"docs?/", r"documentation/", r"examples?/", r"samples?/",
    r"changelog", r"CHANGELOG", r"CHANGES", r"HISTORY",
    r"README", r"LICENSE", r"NOTICE", r"AUTHORS",
    r"\.md$", r"\.txt$", r"\.rst$",
    r"\.yml$", r"\.yaml$", r"\.toml$",
    r"\.json$", r"\.xml$", r"\.csv$", r"\.lock$",
    r"\.png$", r"\.jpg$", r"\.svg$", r"\.gif$",
    r"Makefile$", r"Dockerfile$", r"docker-compose",
    r"\.github/", r"\.circleci/",
    r"vendor/", r"node_modules/", r"dist/", r"build/",
    r"migration", r"seed", r"fixture",
    r"go\.sum$", r"go\.mod$", r"package-lock", r"yarn\.lock",
    r"Cargo\.lock", r"poetry\.lock", r"Gemfile\.lock",
    r"\.min\.js$", r"\.min\.css$", r"\.map$",
    r"generated", r"auto-generated", r"autogen",
    r"\.pb\.go$", r"\.pb\.cc$", r"_pb2\.py$",
    r"swagger", r"openapi",
]

SKIP_MESSAGE_PATTERNS = [
    r"^merge\s",
    r"^merge:",
    r"^auto merge\s",
    r"^rollup of\s",
    r"\bcs fix", r"\bcode style\b", r"\bcoding style\b",
    r"\bphp cs fixer\b",
    r"\bprettier\b", r"\beslint\b", r"\brubocop\b",
    r"\bfmt\b.*\bfix\b",
    r"\btypo\b", r"\bspelling\b",
    r"\btranslat", r"\blocal[ei]", r"\bi18n\b", r"\bl10n\b",
    r"\bdependabot\b", r"\brenovate\b",
    r"\bbump\b.*\bversion\b",
    r"\bupgrade react\b",
    r"\bdrop.*support\b",
    r"\bdeprecate\b",
    r"\brelease\s+\d",
    r"\bchangelog\b",
    r"\bdocument", r"\breadme\b",
    r"regenerat", r"auto.?generat",
    r"\[librarian\]", r"\[bot\]",
]

ADD_PATTERNS = {
    r"\bhmac\b": 8,
    r"\bconstant.?time": 8,
    r"\btiming.?safe": 8,
    r"\bcompare_digest\b": 8,
    r"\bcrypto\.timingSafeEqual\b": 8,
    r"\bexecFile\b": 7,
    r"\bexecFileSync\b": 7,
    r"\bsubprocess\.run\b": 6,
    r"\bshlex\.quote\b": 6,
    r"\bshell\s*=\s*False\b": 6,
    r"\bparameterized\b": 6,
    r"\bprepared.?statement\b": 6,
    r"\bsanitiz\w+\b": 5,
    r"\bhtmlspecialchars\b": 6,
    r"\bhtml\.escape\b": 5,
    r"\bbleach\b": 5,
    r"\bDOMPurify\b": 5,
    r"\bescapeHtml\b": 5,
    r"\brealpath\b": 5,
    r"\bfilepath\.Clean\b": 5,
    r"\bos\.path\.abspath\b": 4,
    r"\bstartswith\b.*\bbase\b": 5,
    r"\bpath\.resolve\b": 3,
    r"\boverride.?access\s*[:=]\s*false\b": 6,
    r"\braise\s+PermissionError\b": 5,
    r"\bForbidden\b": 3,
    r"\bUnauthorized\b": 3,
    r"\bcsrf.?token\b": 6,
    r"\bxsrf\b": 5,
    r"\bweights_only\s*=\s*True\b": 6,
    r"\bsafe_load\b": 6,
    r"\bdefusedxml\b": 6,
    r"\bast\.literal_eval\b": 5,
    r"\bsecure\s*=\s*True\b": 4,
    r"\bhttponly\b": 4,
    r"\bsamesite\b": 4,
    r"\bcontent.?security.?policy\b": 4,
    r"\brate.?limit\b": 4,
    r"\bnonce\b": 3,
    r"\bbounds?.?check\b": 3,
    r"\bmax.?length\b": 2,
    r"\bmax.?size\b": 2,
    r"\bvalidateUrl\b": 5,
    r"\bisPrivateIp\b": 6,
    r"\ballowlist\b": 4,
    r"\bdenylist\b": 4,
    r"\bblocklist\b": 4,
    # PHP-specific
    r"\bhtmlentities\b": 5,
    r"\bfilter_var\b": 5,
    r"\bfilter_input\b": 5,
    r"\bmysqli_prepare\b": 6,
    r"\bPDO::prepare\b": 6,
    r"\bpassword_hash\b": 5,
    r"\bpassword_verify\b": 5,
    r"\brandom_bytes\b": 5,
    r"\brandom_int\b": 5,
    r"\bbin2hex\b": 3,
    r"\bstrip_tags\b": 4,
    r"\bintval\b": 3,
    r"\bpreg_replace_callback\b": 5,
    # Java-specific
    r"\bPreparedStatement\b": 6,
    r"\bParameterizedQuery\b": 6,
    r"\bMessageDigest\.getInstance\b": 4,
    r"\bSecureRandom\b": 5,
    r"\bFiles\.copy\b": 3,
    r"\bProcessBuilder\b": 4,
    # Go-specific
    r"\bfilepath\.EvalSymlinks\b": 5,
    r"\bfilepath\.Abs\b": 4,
    r"\bstrconv\.Atoi\b": 3,
    r"\bcrypto/sha256\b": 4,
    r"\bstrings\.HasPrefix\b": 3,
    # Rust-specific
    r"\bMaybeUninit\b": 5,
    r"\bcatch_unwind\b": 4,
    r"\bfrom_utf8_lossy\b": 3,
    # Python-specific
    r"\bsecrets\.token\b": 5,
    r"\bsubprocess\.check_call\b": 4,
    r"\btempfile\.mkstemp\b": 4,
    r"\bos\.urandom\b": 4,
}

DEL_PATTERNS = {
    r"\bexec\s*\(": 7,
    r"\beval\s*\(": 7,
    r"\bsystem\s*\(": 7,
    r"\bos\.system\b": 7,
    r"\bshell\s*=\s*True\b": 7,
    r"\bexecSync\s*\(": 6,
    r"\bchild_process\.exec\b": 6,
    r"\binnerHTML\s*=": 6,
    r"\bdocument\.write\b": 5,
    r"\bdangerouslySetInnerHTML\b": 6,
    r"\bpickle\.load\b": 6,
    r"\byaml\.load\b": 5,
    r"\btorch\.load\b": 5,
    r"\bmarshall?\.load\b": 5,
    r"\bMD5\b": 4,
    r"\bSHA1\b": 3,
    r"\bDES\b": 4,
    r"\bRC4\b": 4,
    r"\bmath\.random\b": 4,
    r"\brandom\.random\b": 4,
    r"\bverify\s*[:=]\s*false\b": 6,
    r"\btrust.?all\b": 5,
    r"\bno.?verify\b": 5,
    r"\binsecure\b": 4,
    # PHP-specific
    r"\bextract\s*\(": 6,
    r"\bparse_str\s*\(": 6,
    r"\bunserialize\s*\(": 7,
    r"\bpreg_replace\s*\(\s*['\"]/.*/e": 8,
    r"\bcreate_function\s*\(": 7,
    r"\bassert\s*\(": 6,
    r"\bcall_user_func\s*\(": 5,
    r"\bpcntl_exec\s*\(": 7,
    r"\bpassthru\s*\(": 7,
    r"\bshell_exec\s*\(": 7,
    r"\bpopen\s*\(": 6,
    r"\bproc_open\s*\(": 6,
    # Java-specific
    r"\bRuntime\.getRuntime\(\)\.exec\b": 8,
    r"\bObjectInputStream\b": 7,
    r"\bXMLDecoder\b": 7,
    r"\bScriptEngine.*\.eval\b": 7,
    r"\bJNDI\.lookup\b": 8,
    r"\bMethod\.invoke\b": 5,
    # Go-specific
    r"\bexec\.Command\b": 6,
    r"\bioutil\.ReadAll\b": 3,
    r"\bhttp\.ListenAndServe\b.*0\.0\.0\.0": 5,
    # Rust-specific
    r"\bunsafe\s*\{": 5,
    r"\btransmute\b": 6,
    r"\buninitialized\b": 6,
    r"\b\.unwrap\(\)": 3,
    # Python-specific
    r"\bos\.popen\b": 6,
    r"\bcommands\.getoutput\b": 6,
    r"\btempfile\.mktemp\b": 5,
    r"\bshelve\.open\b": 5,
    r"\bcPickle\b": 6,
    r"\bimportlib\.import_module\b": 4,
    r"\blogging\.config\.dictConfig\b": 4,
    # C/C++ specific
    r"\bstrcpy\s*\(": 7,
    r"\bgets\s*\(": 8,
    r"\bsprintf\s*\(": 6,
    r"\bstrcat\s*\(": 6,
    r"\bmalloc\s*\(": 3,
    # JavaScript/Node additional
    r"\bFunction\s*\(": 7,
    r"\bsetTimeout\s*\(\s*['\"]": 6,
    r"\bsetInterval\s*\(\s*['\"]": 6,
    r"\brequire\s*\(\s*[^'\"]": 6,
    r"\bvm\.runInThisContext\b": 7,
}

REPLACEMENT_PAIRS = [
    (r"\bexec\b", r"\bexecFile\b", 8),
    (r"\bexecSync\b", r"\bexecFileSync\b", 8),
    (r"\binnerHTML\b", r"\btextContent\b", 7),
    (r"\binnerHTML\b", r"\bescapeHtml\b", 7),
    (r"\b==\b", r"\bcompare_digest\b", 8),
    (r"\b==\b", r"\btimingSafeEqual\b", 8),
    (r"\b==\b", r"\bhash_equals\b", 7),
    (r"\bMD5\b", r"\bSHA256\b", 5),
    (r"\bMD5\b", r"\bbcrypt\b", 7),
    (r"\bSHA1\b", r"\bSHA256\b", 4),
    (r"\bpickle\.load\b", r"\bjson\.load\b", 6),
    (r"\byaml\.load\b", r"\byaml\.safe_load\b", 7),
    (r"\btorch\.load\b", r"\bweights_only\b", 6),
    (r"\bparseString\b", r"\bdefusedxml\b", 6),
    (r"\brandom\.random\b", r"\bsecrets\b", 6),
    (r"\bmath\.random\b", r"\bcrypto\.randomBytes\b", 6),
    (r"\bexec\b", r"\bsubprocess\.run\b", 6),
    (r"\bhttp://", r"\bhttps://", 3),
    # PHP
    (r"\bunserialize\b", r"\bjson_decode\b", 7),
    (r"\bextract\b", r"\b\$_POST\[", 5),
    (r"\bpreg_replace\b.*/e", r"\bpreg_replace_callback\b", 8),
    (r"\bserialize\b", r"\bjson_encode\b", 5),
    (r"\bcreate_function\b", r"\bfunction\s*\(", 6),
    # Java
    (r"\bRuntime.*exec\b", r"\bProcessBuilder\b", 7),
    (r"\bObjectInputStream\b", r"\bJSON\b", 7),
    (r"\bXMLDecoder\b", r"\bJSON\b", 7),
    # C
    (r"\bstrcpy\b", r"\bstrncpy\b", 6),
    (r"\bsprintf\b", r"\bsnprintf\b", 6),
    (r"\bgets\b", r"\bfgets\b", 7),
    # Python
    (r"\btempfile\.mktemp\b", r"\btempfile\.mkstemp\b", 6),
    (r"\bos\.popen\b", r"\bsubprocess\.run\b", 6),
    # Rust
    (r"\bunsafe\b", r"\bsafe\b", 5),
    (r"\b\.unwrap\(\)", r"\b\.unwrap_or\b", 4),
    # Go
    (r"\bexec\.Command\b", r"\bexec\.CommandContext\b", 5),
    (r"\bstrings\.Contains\b", r"\bstrings\.HasPrefix\b", 4),
    # Node
    (r"\bcrypto\.createCipher\b", r"\bcrypto\.createCipheriv\b", 6),
    # JS
    (r"\blocation\.href\s*=", r"\bsanitizeUrl\b", 6),
    (r"\bObject\.assign\b", r"\bstructuredClone\b", 5),
]

MAX_FILES_SCORED = 5
MAX_SCORE_PER_FILE = 15
THRESHOLD = 12
MAX_TOTAL_FILES = 50
MAX_CHANGES_PER_FILE = 200


def score_commit(commit_message: str, files_changed: list[dict]) -> dict:
    total_score = 0
    breakdown = []
    matched_files = []

    msg_lower = commit_message.lower()

    for pattern in SKIP_MESSAGE_PATTERNS:
        if _search(pattern, msg_lower):
            return {
                "score": 0,
                "normalized_score": 0,
                "threshold_met": False,
                "breakdown": [{"signal": "skip_message", "score": 0, "detail": pattern}],
                "files": [],
            }

    total_files = len(files_changed)
    if total_files > MAX_TOTAL_FILES:
        return {
            "score": 0,
            "normalized_score": 0,
            "threshold_met": False,
            "breakdown": [{"signal": "bulk_change", "score": 0, "detail": f"{total_files} files"}],
            "files": [],
        }

    security_msg_words = [
        "fix", "patch", "security", "vuln", "overflow", "inject",
        "sanitiz", "bypass", "traversal", "xss", "csrf", "ssrf",
        "rce", "dos", "permission", "privilege", "leak",
        "harden", "mitigat", "restrict",
        "validation", "authentication", "authorization", "bounds",
        "hotfix", "critical", "guard", "protect", "safeguard",
        "defensive", "constrain", "strengthen", "lockdown",
    ]
    msg_hits = [w for w in security_msg_words if w in msg_lower]

    if msg_hits:
        msg_score = min(len(msg_hits) * 2, 5)
        total_score += msg_score
        breakdown.append({"signal": "commit_message", "score": msg_score, "detail": ", ".join(msg_hits)})

    for file_info in files_changed:
        file_path = file_info.get("filename", "")
        patch = file_info.get("patch", "")

        if not patch:
            continue

        path_lower = file_path.lower()

        skip = False
        for pattern in SKIP_FILE_PATTERNS:
            if _search(pattern, path_lower):
                skip = True
                break
        if skip:
            continue

        file_score = 0
        file_breakdown = []

        for pattern, weight in SECURITY_FILE_PATTERNS_HIGH:
            if _search(pattern, path_lower):
                file_score += weight
                file_breakdown.append(f"sec_file:{pattern}")
                break

        if file_score == 0:
            for pattern, weight in SECURITY_FILE_PATTERNS_LOW:
                if _search(pattern, path_lower):
                    file_score += weight
                    file_breakdown.append(f"sec_file:{pattern}")
                    break

        added_lines = []
        removed_lines = []
        for line in patch.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                removed_lines.append(line[1:])

        change_count = len(added_lines) + len(removed_lines)
        if change_count > MAX_CHANGES_PER_FILE:
            continue

        if 1 <= change_count <= 20:
            file_score += 3
            file_breakdown.append("surgical")
        elif 20 < change_count <= 60:
            file_score += 1
            file_breakdown.append("moderate")
        elif change_count > 100:
            file_score -= 2
            file_breakdown.append("large_penalty")

        added_text = "\n".join(added_lines)
        removed_text = "\n".join(removed_lines)

        add_matched = set()
        for pattern, weight in ADD_PATTERNS.items():
            match = _search(pattern, added_text, re.IGNORECASE)
            if match:
                token = match.group()
                if token.lower() not in add_matched:
                    file_score += weight
                    file_breakdown.append(f"+{token}")
                    add_matched.add(token.lower())

        del_matched = set()
        for pattern, weight in DEL_PATTERNS.items():
            match = _search(pattern, removed_text, re.IGNORECASE)
            if match:
                token = match.group()
                if token.lower() not in del_matched:
                    file_score += weight
                    file_breakdown.append(f"-{token}")
                    del_matched.add(token.lower())

        for del_pat, add_pat, weight in REPLACEMENT_PAIRS:
            if _search(del_pat, removed_text, re.IGNORECASE) and _search(
                add_pat, added_text, re.IGNORECASE
            ):
                file_score += weight
                file_breakdown.append(f"swap:{del_pat}→{add_pat}")

        if file_score > 0:
            capped_score = min(file_score, MAX_SCORE_PER_FILE)
            matched_files.append({
                "file": file_path,
                "score": capped_score,
                "raw_score": file_score,
                "signals": file_breakdown,
                "added_sample": added_text[:500],
                "removed_sample": removed_text[:500],
            })

    matched_files.sort(key=lambda f: f["score"], reverse=True)
    top_files = matched_files[:MAX_FILES_SCORED]

    files_score = sum(f["score"] for f in top_files)
    total_score += files_score

    max_possible = (MAX_FILES_SCORED * MAX_SCORE_PER_FILE) + 5
    normalized = min(round((total_score / max_possible) * 100, 1), 100)

    return {
        "score": total_score,
        "normalized_score": normalized,
        "threshold_met": total_score >= THRESHOLD,
        "breakdown": breakdown,
        "files": top_files,
    }