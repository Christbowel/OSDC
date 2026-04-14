import re
from pathlib import PurePosixPath


SECURITY_FILE_PATTERNS = [
    r"auth", r"login", r"session", r"token", r"credential", r"password",
    r"crypto", r"cipher", r"encrypt", r"decrypt", r"hash", r"hmac", r"sign",
    r"permission", r"privilege", r"access", r"policy", r"role", r"acl",
    r"sanitiz", r"validat", r"filter", r"escap", r"encod",
    r"security", r"vuln", r"exploit",
    r"parser", r"deserializ", r"unmarshal", r"decode",
    r"handler", r"middleware", r"interceptor", r"guard",
    r"sql", r"query", r"database", r"db\.py", r"db\.go", r"db\.js",
    r"upload", r"download", r"file", r"path", r"directory",
    r"redirect", r"cors", r"origin", r"header", r"cookie",
    r"rate.?limit", r"throttl", r"timeout",
    r"webhook", r"callback", r"endpoint",
]

SKIP_FILE_PATTERNS = [
    r"test[_/]", r"_test\.", r"\.test\.", r"spec[_/]", r"__tests__",
    r"docs?/", r"documentation/", r"examples?/", r"samples?/",
    r"changelog", r"CHANGELOG", r"CHANGES", r"HISTORY",
    r"README", r"LICENSE", r"NOTICE", r"AUTHORS",
    r"\.md$", r"\.txt$", r"\.rst$", r"\.yml$", r"\.yaml$",
    r"\.json$", r"\.xml$", r"\.csv$", r"\.lock$",
    r"\.png$", r"\.jpg$", r"\.svg$", r"\.gif$",
    r"Makefile$", r"Dockerfile$", r"docker-compose",
    r"\.github/", r"\.circleci/",
    r"vendor/", r"node_modules/", r"dist/", r"build/",
    r"migration", r"seed", r"fixture",
]

ADD_PATTERNS_HIGH = {
    r"\bhmac\b": 5,
    r"\bconstant.?time": 5,
    r"\btiming.?safe": 5,
    r"\bcompare_digest\b": 5,
    r"\bcrypto\.timingSafeEqual\b": 5,
    r"\bexecFile\b": 5,
    r"\bexecFileSync\b": 5,
    r"\bsubprocess\.run\b": 4,
    r"\bshlex\.quote\b": 4,
    r"\bparameterized\b": 4,
    r"\bprepared.?statement\b": 4,
    r"\bplaceholder\b": 3,
    r"\bsanitiz\w+\b": 4,
    r"\bhtmlspecialchars\b": 4,
    r"\bhtml\.escape\b": 4,
    r"\bmarkup\.escape\b": 4,
    r"\bbleach\b": 4,
    r"\bDOMPurify\b": 4,
    r"\btextContent\b": 3,
    r"\binnerText\b": 3,
    r"\bescapeHtml\b": 4,
    r"\bencodeURIComponent\b": 3,
    r"\brealpath\b": 4,
    r"\bfilepath\.Clean\b": 4,
    r"\bpath\.normalize\b": 3,
    r"\bstartswith\b": 3,
    r"\bstartsWith\b": 3,
    r"\bpath\.resolve\b": 3,
    r"\bos\.path\.abspath\b": 3,
    r"\bvalidat\w+\b": 3,
    r"\bverif\w+\b": 3,
    r"\bauthoriz\w+\b": 3,
    r"\bauthenticat\w+\b": 3,
    r"\bbounds?.?check\b": 3,
    r"\blength.?check\b": 2,
    r"\bsize.?check\b": 2,
    r"\bmax.?length\b": 2,
    r"\bmax.?size\b": 2,
    r"\brate.?limit\b": 3,
    r"\bthrottl\w+\b": 3,
    r"\bnonce\b": 3,
    r"\bcsrf\b": 4,
    r"\bxsrf\b": 4,
    r"\bweights_only\s*=\s*True\b": 4,
    r"\bsafe_load\b": 4,
    r"\bdefusedxml\b": 4,
    r"\bsecure\s*=\s*True\b": 3,
    r"\bhttponly\b": 3,
    r"\bsamesite\b": 3,
    r"\bstrict.?transport\b": 3,
    r"\bcontent.?security.?policy\b": 3,
    r"\bx.?frame.?options\b": 2,
    r"\boverride.?access\s*[:=]\s*false\b": 4,
    r"\braise\s+PermissionError\b": 3,
    r"\braise\s+ValueError\b": 2,
    r"\bforbidden\b": 2,
    r"\bunauthorized\b": 2,
}

DEL_PATTERNS_HIGH = {
    r"\bexec\s*\(": 5,
    r"\beval\s*\(": 5,
    r"\bsystem\s*\(": 5,
    r"\bos\.system\b": 5,
    r"\bshell\s*=\s*True\b": 5,
    r"\bexecSync\b": 4,
    r"\bchild_process\.exec\b": 4,
    r"\binnerHTML\b": 4,
    r"\bdocument\.write\b": 4,
    r"\bdangerouslySetInnerHTML\b": 4,
    r"\bf['\"].*\{.*\}": 3,
    r"\bstring\.format\b": 2,
    r"\b%s\b.*query": 3,
    r"\bMD5\b": 3,
    r"\bSHA1\b": 2,
    r"\bDES\b": 3,
    r"\bRC4\b": 3,
    r"\bmath\.random\b": 3,
    r"\brandom\.random\b": 3,
    r"\bpickle\.load\b": 4,
    r"\byaml\.load\b": 3,
    r"\btorch\.load\b": 3,
    r"\bmarshall\.load\b": 3,
    r"\b==\b": 1,
    r"\b!=\b": 1,
}

REPLACEMENT_PAIRS = [
    (r"\bexec\b", r"\bexecFile\b", 5),
    (r"\bexecSync\b", r"\bexecFileSync\b", 5),
    (r"\binnerHTML\b", r"\btextContent\b", 5),
    (r"\b==\b", r"\bhmac\b", 5),
    (r"\b==\b", r"\btimingSafeEqual\b", 5),
    (r"\b==\b", r"\bcompare_digest\b", 5),
    (r"\bMD5\b", r"\bSHA256\b", 4),
    (r"\bMD5\b", r"\bbcrypt\b", 5),
    (r"\bSHA1\b", r"\bSHA256\b", 3),
    (r"\bpickle\.load\b", r"\bjson\.load\b", 4),
    (r"\byaml\.load\b", r"\byaml\.safe_load\b", 5),
    (r"\btorch\.load\b", r"\bweights_only\b", 4),
    (r"\bhttp://\b", r"\bhttps://\b", 2),
    (r"\bparseString\b", r"\bdefusedxml\b", 4),
    (r"\bos\.path\.join\b", r"\brealpath\b", 4),
    (r"\bfilepath\.Join\b", r"\bfilepath\.Clean\b", 4),
    (r"\bformat\b.*query", r"\bparameterized\b", 4),
    (r"\bexec\b", r"\bsubprocess\.run\b", 4),
    (r"\brandom\.random\b", r"\bsecrets\b", 4),
    (r"\bmath\.random\b", r"\bcrypto\.randomBytes\b", 4),
]


def score_commit(commit_message: str, files_changed: list[dict]) -> dict:
    total_score = 0
    breakdown = []
    matched_files = []

    msg_lower = commit_message.lower()
    msg_security_words = [
        "fix", "patch", "security", "vuln", "overflow", "inject",
        "sanitiz", "bypass", "traversal", "xss", "csrf", "ssrf",
        "rce", "dos", "auth", "permission", "privilege", "leak",
    ]
    msg_hits = [w for w in msg_security_words if w in msg_lower]
    if msg_hits:
        msg_score = min(len(msg_hits) * 1, 3)
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
            if re.search(pattern, path_lower):
                skip = True
                break
        if skip:
            continue

        file_score = 0
        file_breakdown = []

        for pattern in SECURITY_FILE_PATTERNS:
            if re.search(pattern, path_lower):
                file_score += 3
                file_breakdown.append(f"security_file:{pattern}")
                break

        added_lines = []
        removed_lines = []
        for line in patch.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                removed_lines.append(line[1:])

        change_count = len(added_lines) + len(removed_lines)
        if 1 <= change_count <= 30:
            file_score += 2
            file_breakdown.append("surgical_change")
        elif 30 < change_count <= 80:
            file_score += 1
            file_breakdown.append("moderate_change")

        added_text = "\n".join(added_lines)
        removed_text = "\n".join(removed_lines)

        for pattern, weight in ADD_PATTERNS_HIGH.items():
            if re.search(pattern, added_text, re.IGNORECASE):
                file_score += weight
                match = re.search(pattern, added_text, re.IGNORECASE)
                file_breakdown.append(f"add:{match.group()}")

        for pattern, weight in DEL_PATTERNS_HIGH.items():
            if re.search(pattern, removed_text, re.IGNORECASE):
                file_score += weight
                match = re.search(pattern, removed_text, re.IGNORECASE)
                file_breakdown.append(f"del:{match.group()}")

        for del_pat, add_pat, weight in REPLACEMENT_PAIRS:
            if re.search(del_pat, removed_text, re.IGNORECASE) and re.search(add_pat, added_text, re.IGNORECASE):
                file_score += weight
                file_breakdown.append(f"replace:{del_pat}->{add_pat}")

        if file_score > 0:
            matched_files.append({
                "file": file_path,
                "score": file_score,
                "signals": file_breakdown,
                "added_sample": added_text[:500],
                "removed_sample": removed_text[:500],
            })
            total_score += file_score

    return {
        "score": total_score,
        "threshold_met": total_score >= 8,
        "breakdown": breakdown,
        "files": sorted(matched_files, key=lambda f: f["score"], reverse=True),
    }