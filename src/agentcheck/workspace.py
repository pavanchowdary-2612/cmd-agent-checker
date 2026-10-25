"""Bounded, repository-aware source and harness inventory."""

from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess
import os
import io
import tokenize

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", ".agentcheck", "venv", "env", "node_modules", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".next", "coverage",
}
EXCLUDED_TEST_DIRS = {"test", "tests", "__tests__", "unit_tests", "integration_tests", "e2e", "spec", "specs"}
TEXT_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt",
    ".go", ".rs", ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift",
    ".scala", ".sh", ".bash", ".ps1", ".sql", ".md", ".mdx", ".rst", ".txt", ".toml",
    ".yaml", ".yml", ".json", ".ipynb", ".ini", ".cfg", ".conf", ".properties", ".xml",
    ".html", ".css", ".proto", ".tf", ".hcl", ".gradle", ".ex", ".exs", ".dart", ".vue",
    ".svelte", ".prompt", ".j2", ".jinja", ".env.example", ".pem", ".key",
}
IMPORTANT_NAMES = {"dockerfile", "makefile", "justfile", ".gitignore", ".dockerignore", ".env.example"}
MAX_FILE_BYTES = 512_000
MAX_CONTEXT_CHARS = 500_000
_SECRET_VALUE = re.compile(r"(?i)((?:api[_-]?key|secret|token|password|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[=:]\s*)(['\"])(?!\$|%)([^'\"]{12,})\2")
_KNOWN_TOKEN = re.compile(r"(?i)\b(?:gsk_[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
_EMAIL_VALUE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_CARD_VALUE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PHONE_VALUE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{2,4}\)?[ .-]?)?\d{3,4}[ .-]?\d{3,4}(?!\w)")
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.S)


def _redact_phone(match: re.Match) -> str:
    return "[PHONE REDACTED]" if len(re.sub(r"\D", "", match.group(0))) >= 10 else match.group(0)


def _mask_span(text: str, start: tuple[int, int], end: tuple[int, int]) -> str:
    lines = text.splitlines(keepends=True)
    for line_index in range(start[0] - 1, min(end[0], len(lines))):
        left = start[1] if line_index == start[0] - 1 else 0
        right = end[1] if line_index == end[0] - 1 else len(lines[line_index].rstrip("\r\n"))
        lines[line_index] = lines[line_index][:left] + re.sub(r"[^\r\n]", " ", lines[line_index][left:right]) + lines[line_index][right:]
    return "".join(lines)


def analysis_text(path: str, content: str) -> str:
    """Return analysis input with comments and Markdown code examples masked, preserving lines."""
    suffix = Path(path).suffix.lower()
    if suffix in {".md", ".mdx", ".rst"}:
        lines = content.splitlines(keepends=True)
        inside_fence = False
        fence = ""
        for index, line in enumerate(lines):
            marker = re.match(r"^\s*(```+|~~~+)", line)
            if marker:
                token = marker.group(1)
                if not inside_fence:
                    inside_fence, fence = True, token[0]
                    lines[index] = re.sub(r"[^\r\n]", " ", line)
                elif token[0] == fence:
                    inside_fence, fence = False, ""
                    lines[index] = re.sub(r"[^\r\n]", " ", line)
            elif inside_fence:
                lines[index] = re.sub(r"[^\r\n]", " ", line)
        content = "".join(lines)
        markers = ("<!--",)
    elif suffix == ".py":
        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
            for token in reversed(tokens):
                if token.type == tokenize.COMMENT:
                    content = _mask_span(content, token.start, token.end)
        except (tokenize.TokenError, IndentationError):
            pass
        return content
    else:
        lower_path = path.casefold()
        if lower_path.endswith(".env.example") or Path(path).name.casefold() in {"dockerfile", "makefile", "justfile", ".gitignore", ".dockerignore"}:
            markers = ("#",)
        elif suffix in {".html", ".xml", ".vue", ".svelte"}:
            markers = ("<!--",)
        elif suffix in {".sql", ".lua"}:
            markers = ("/*", "--")
        elif suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".ps1", ".tf", ".hcl", ".properties", ".ex", ".exs"}:
            markers = ("#",)
        elif suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift", ".scala", ".gradle", ".css", ".dart"}:
            markers = ("/*", "//")
        else:
            markers = ()

    # Mask language comments outside quoted strings, including inline comments.
    output = list(content)
    index = 0
    quote = ""
    escaped = False
    while index < len(content):
        char = content[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        marker = next((value for value in markers if content.startswith(value, index)), None)
        if marker:
            block = marker in {"/*", "<!--"}
            closing = "*/" if marker == "/*" else "-->" if marker == "<!--" else None
            end = content.find(closing, index + len(marker)) if block else -1
            end = len(content) if block and end < 0 else end + len(closing) if block else content.find("\n", index)
            end = len(content) if end < 0 else end
            for position in range(index, end):
                if output[position] not in "\r\n":
                    output[position] = " "
            index = end
            continue
        index += 1
    return "".join(output)


@dataclass
class SourceFile:
    path: str
    content: str
    bytes: int
    sensitive_file: bool = False


@dataclass
class Inventory:
    root: Path
    files: list[SourceFile]
    skipped_large: list[str]
    unreadable: list[str]
    harness_files: list[str]
    is_agent_candidate: bool
    environment_files: list[dict[str, object]] = field(default_factory=list)


def _git_file_state(root: Path, relative: str) -> tuple[bool | None, bool | None]:
    """Return tracked and ignored status without opening the environment file."""
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative],
            cwd=root, capture_output=True, text=True, timeout=5, check=False, shell=False,
        )
        is_tracked = tracked.returncode == 0 if tracked.returncode in {0, 1} else None
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", relative],
            cwd=root, capture_output=True, text=True, timeout=5, check=False, shell=False,
        )
        is_ignored = ignored.returncode == 0 if ignored.returncode in {0, 1} else None
        return is_tracked, is_ignored
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def inventory_repository(root: Path) -> Inventory:
    root = root.resolve()
    included: list[SourceFile] = []
    skipped: list[str] = []
    unreadable: list[str] = []
    environment_files: list[dict[str, object]] = []
    for current, dirs, filenames in os.walk(root, topdown=True):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if name.casefold() not in SKIP_DIRS and name.casefold() not in EXCLUDED_TEST_DIRS]
        for filename in filenames:
            path = current_path / filename
            is_dotenv = path.name.lower() == ".env" or path.name.lower().startswith(".env.") and path.name.lower() != ".env.example"
            if is_dotenv:
                relative = path.relative_to(root).as_posix()
                tracked, ignored = _git_file_state(root, relative)
                environment_files.append({"path": relative, "git_tracked": tracked, "git_ignored": ignored})
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name.lower() not in IMPORTANT_NAMES:
                continue
            relative = path.relative_to(root).as_posix()
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    skipped.append(relative)
                    continue
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                unreadable.append(relative)
                continue
            included.append(SourceFile(relative, content, size, path.suffix.lower() in {".pem", ".key"}))
    included.sort(key=lambda item: item.path.casefold())
    harness_files = [item.path for item in included if any(token in item.path.lower() for token in ("harness", "eval", "benchmark", "scenario", "golden"))]
    all_text = "\n".join(item.content for item in included)
    framework = bool(re.search(
        r"\b(?:from|import)\s+(?:langchain(?:[._][\w]+)*|openai|anthropic|groq|llama_index|transformers|ollama|crewai|autogen)\b",
        all_text, re.I,
    ))
    has_tool = bool(re.search(
        r"@(?:[\w]+\.)*(?:tool|action|command)\b|\b(?:def|function|async\s+function)\s+\w*(?:tool|action|agent)\w*|\.(?:bind_tools|call_tool|list_tools)\s*\(|\b(?:FastMCP|MCPServer|ClientSession)\b",
        all_text, re.I,
    ))
    return Inventory(root, included, skipped, unreadable, harness_files, framework and has_tool, environment_files)


def model_context_files(inventory: Inventory) -> tuple[dict[str, str], list[str]]:
    """Return per-file model input after comments, examples, and sensitive values are redacted."""
    safe_files: dict[str, str] = {}
    omitted = []
    remaining = MAX_CONTEXT_CHARS
    for item in inventory.files:
        if item.sensitive_file:
            omitted.append(item.path)
            continue
        safe_content = analysis_text(item.path, item.content)
        safe_content = _PRIVATE_KEY_BLOCK.sub("[PRIVATE KEY REDACTED]", safe_content)
        safe_content = _SECRET_VALUE.sub(r"\1\2[REDACTED]\2", safe_content)
        safe_content = _KNOWN_TOKEN.sub("[CREDENTIAL REDACTED]", safe_content)
        safe_content = _EMAIL_VALUE.sub("[EMAIL REDACTED]", safe_content)
        safe_content = _CARD_VALUE.sub("[NUMBER REDACTED]", safe_content)
        safe_content = _PHONE_VALUE.sub(_redact_phone, safe_content)
        block = f"\n--- FILE: {item.path} ---\n{safe_content}\n"
        if len(block) > remaining:
            omitted.append(item.path)
            continue
        safe_files[item.path] = safe_content
        remaining -= len(block)
    return safe_files, omitted


def model_context(inventory: Inventory) -> tuple[str, list[str]]:
    safe_files, omitted = model_context_files(inventory)
    parts = [f"\n--- FILE: {path} ---\n{content}\n" for path, content in safe_files.items()]
    return "".join(parts), omitted
