"""Context-aware wordlist generation helpers for fuzzing stages."""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qs, urlparse


_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{1,40}")
_STOP_WORDS = {
    "http",
    "https",
    "www",
    "com",
    "html",
    "php",
    "asp",
    "aspx",
    "jsp",
    "json",
    "xml",
    "js",
    "css",
    "png",
    "jpg",
    "jpeg",
    "svg",
    "woff",
    "woff2",
    "static",
    "assets",
    "images",
    "scripts",
}


def derive_context_words(urls: list[str], max_words: int = 120) -> list[str]:
    """Extract candidate ffuf words from discovered URLs and query keys."""
    counter: Counter[str] = Counter()
    for raw in urls:
        url = str(raw or "").strip()
        if not url:
            continue
        parsed = urlparse(url)

        path_tokens = _TOKEN_RE.findall(parsed.path.replace("/", " "))
        query_tokens = []
        query_map = parse_qs(parsed.query, keep_blank_values=True)
        for key in query_map.keys():
            query_tokens.extend(_TOKEN_RE.findall(key))

        # Route-like hints from URL fragments and filenames.
        fragment_tokens = _TOKEN_RE.findall(parsed.fragment.replace("/", " "))
        filename = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
        filename_tokens = _TOKEN_RE.findall(filename.replace(".", " "))

        for token in [*path_tokens, *query_tokens, *fragment_tokens, *filename_tokens]:
            lowered = token.lower()
            if lowered in _STOP_WORDS:
                continue
            if lowered.isdigit():
                continue
            counter[lowered] += 1

    words = [word for word, _ in counter.most_common(max(10, int(max_words)))]
    return words
