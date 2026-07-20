#!/usr/bin/env python3
"""Validate relative file links in tracked Markdown documents."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import urllib.parse
from collections.abc import Iterable, Iterator


ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCE_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(.*)$", re.MULTILINE)
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})([^\r\n]*)$")
FENCE_CLOSE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*$")
def tracked_markdown(root: pathlib.Path = ROOT) -> list[pathlib.Path]:
    output = subprocess.check_output(["git", "ls-files", "-z", "*.md"], cwd=root)
    return [root / item.decode() for item in output.split(b"\0") if item]


def _inline_target_end(text: str, start: int) -> int | None:
    """Return the closing parenthesis for one inline link destination."""
    cursor = start
    destination_depth = 0
    phase = "destination"
    title_delimiter = ""

    while cursor < len(text):
        char = text[cursor]
        if char == "\\" and cursor + 1 < len(text):
            cursor += 2
            continue

        if phase == "destination":
            if cursor == start and char == "<":
                phase = "angle_destination"
            elif char.isspace() and destination_depth == 0:
                phase = "after_destination"
            elif char == "(":
                destination_depth += 1
            elif char == ")":
                if destination_depth == 0:
                    return cursor
                destination_depth -= 1
        elif phase == "angle_destination":
            if char == ">":
                phase = "after_destination"
        elif phase == "after_destination":
            if char.isspace():
                pass
            elif char in {'"', "'"}:
                title_delimiter = char
                phase = "quoted_title"
            elif char == "(":
                phase = "parenthesized_title"
            elif char == ")":
                return cursor
            else:
                return None
        elif phase == "quoted_title":
            if char == title_delimiter:
                phase = "after_title"
        elif phase == "parenthesized_title":
            if char == ")":
                phase = "after_title"
        elif phase == "after_title":
            if char.isspace():
                pass
            elif char == ")":
                return cursor
            else:
                return None
        cursor += 1

    return None


def inline_link_targets(text: str) -> Iterator[str]:
    """Yield inline destinations, respecting destinations and optional titles."""
    index = 0
    while index < len(text) - 1:
        if text[index] == "\\":
            index += 2
            continue
        if text[index] != "]" or text[index + 1] != "(":
            index += 1
            continue

        start = index + 2
        end = _inline_target_end(text, start)
        if end is None:
            index = start
            continue
        yield text[start:end]
        index = end + 1


def _blank_line(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[-1]
    return ""


def strip_fenced_code(text: str) -> str:
    """Blank CommonMark fenced blocks while preserving line boundaries."""
    output: list[str] = []
    fence_char = ""
    fence_length = 0

    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if not fence_char:
            opener = FENCE_OPEN.match(content)
            if opener and not (
                opener.group(1).startswith("`") and "`" in opener.group(2)
            ):
                fence_char = opener.group(1)[0]
                fence_length = len(opener.group(1))
                output.append(_blank_line(line))
                continue
            output.append(line)
            continue

        closer = FENCE_CLOSE.match(content)
        if (
            closer
            and closer.group(1)[0] == fence_char
            and len(closer.group(1)) >= fence_length
        ):
            fence_char = ""
            fence_length = 0
        output.append(_blank_line(line))

    return "".join(output)


def strip_inline_code(text: str) -> str:
    """Blank matched CommonMark backtick code spans, including multiline spans."""
    chars = list(text)
    index = 0
    while index < len(text):
        if text[index] != "`":
            index += 1
            continue

        opener_end = index
        while opener_end < len(text) and text[opener_end] == "`":
            opener_end += 1
        opener_length = opener_end - index
        cursor = opener_end
        closing_end = -1
        while cursor < len(text):
            next_tick = text.find("`", cursor)
            if next_tick < 0:
                break
            run_end = next_tick
            while run_end < len(text) and text[run_end] == "`":
                run_end += 1
            if run_end - next_tick == opener_length:
                closing_end = run_end
                break
            cursor = run_end

        if closing_end < 0:
            index = opener_end
            continue
        for position in range(index, closing_end):
            if chars[position] not in "\r\n":
                chars[position] = " "
        index = closing_end

    return "".join(chars)


def _unescape_markdown(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def link_target(raw: str) -> str:
    value = raw.strip()
    if value.startswith("<"):
        escaped = False
        for index, char in enumerate(value[1:], start=1):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == ">":
                return _unescape_markdown(value[1:index])
        return _unescape_markdown(value[1:])

    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char.isspace():
            return _unescape_markdown(value[:index])
    return _unescape_markdown(value)


def relative_target(
    source: pathlib.Path, raw: str, root: pathlib.Path = ROOT
) -> pathlib.Path | None:
    target = link_target(raw)
    if not target or target.startswith("#"):
        return None
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc or target.startswith("//"):
        return None
    path_text = urllib.parse.unquote(target.split("#", 1)[0].split("?", 1)[0])
    if not path_text:
        return None
    if path_text.startswith("/"):
        return root / path_text.lstrip("/")
    return source.parent / path_text


def markdown_targets(text: str) -> Iterator[str]:
    searchable = strip_inline_code(strip_fenced_code(text))
    yield from inline_link_targets(searchable)
    for match in REFERENCE_DEFINITION.finditer(searchable):
        yield match.group(1)


def broken_links(root: pathlib.Path, sources: Iterable[pathlib.Path]) -> list[str]:
    errors: list[str] = []
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for raw in markdown_targets(text):
            target = relative_target(source, raw, root)
            if target is not None and not target.resolve().exists():
                errors.append(f"{source.relative_to(root)} -> {link_target(raw)}")
    return sorted(set(errors))


def main() -> int:
    errors = broken_links(ROOT, tracked_markdown())
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
