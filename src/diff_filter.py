from pathlib import PurePosixPath
from src.config import (
    EXCLUDED_EXTENSIONS, EXCLUDED_PATTERNS,
    SECURITY_KEYWORDS, MAX_DIFF_FILES, MAX_DIFF_LINES,
)


def filter_diff(raw_diff: str) -> str:
    file_diffs = _split_into_files(raw_diff)
    scored_files = []

    for file_path, file_content in file_diffs:
        if _is_excluded(file_path):
            continue
        score = _compute_relevance(file_path, file_content)
        scored_files.append((score, file_path, file_content))

    scored_files.sort(key=lambda x: x[0], reverse=True)
    selected = scored_files[:MAX_DIFF_FILES]

    filtered_parts = []
    for _, file_path, file_content in selected:
        truncated = _truncate_diff(file_content)
        filtered_parts.append(f"--- {file_path}\n{truncated}")

    return "\n\n".join(filtered_parts)


def _split_into_files(raw_diff: str) -> list[tuple[str, str]]:
    files = []
    current_path = None
    current_lines = []

    for line in raw_diff.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if current_path:
                files.append((current_path, "".join(current_lines)))
            parts = line.strip().split(" b/")
            current_path = parts[-1] if len(parts) > 1 else "unknown"
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_path:
        files.append((current_path, "".join(current_lines)))

    return files


def _is_excluded(file_path: str) -> bool:
    path = PurePosixPath(file_path)
    suffix = path.suffix.lower()

    if suffix in EXCLUDED_EXTENSIONS:
        return True

    path_lower = file_path.lower()
    for pattern in EXCLUDED_PATTERNS:
        if pattern.lower() in path_lower:
            return True

    return False


def _compute_relevance(file_path: str, content: str) -> int:
    score = 0
    combined = (file_path + content).lower()

    for keyword in SECURITY_KEYWORDS:
        if keyword in combined:
            score += 10

    change_lines = sum(
        1 for line in content.splitlines()
        if line.startswith("+") or line.startswith("-")
    )
    if 5 <= change_lines <= 100:
        score += 20
    elif change_lines > 100:
        score += 5

    return score


def _truncate_diff(content: str) -> str:
    lines = content.splitlines(keepends=True)
    if len(lines) <= MAX_DIFF_LINES:
        return content
    return "".join(lines[:MAX_DIFF_LINES])
