"""Central English locale catalog access for web templates (T9-A).

Keys live in ``config/locales/en.json``; ``t`` falls back to the key
itself so a missing entry is visible but never breaks rendering.
"""

import json
from pathlib import Path

LOCALES_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "locales"


def load_catalog(locale: str = "en") -> dict[str, str]:
    path = LOCALES_DIR / f"{locale}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(k, str)}


_CATALOG = load_catalog("en")


def t(key: str, **values: object) -> str:
    """Look up ``key``; English fallback is the catalog itself."""
    template = _CATALOG.get(key, key)
    if not values:
        return template
    try:
        return template.format(**values)
    except (KeyError, ValueError):
        return template
