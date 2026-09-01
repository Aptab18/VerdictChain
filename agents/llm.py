"""Provider-agnostic LLM access for the agents.

Both agents used to embed their own Groq client, which meant a provider change
had to be made twice and could drift. They now share this one adapter.

Supported providers, chosen automatically from whichever key is present:

    Gemini  (google-genai)  -- GEMINI_API_KEY / GOOGLE_API_KEY
    Groq    (groq)          -- GROQ_API_KEY, keys begin with "gsk_"

Because a key pasted into the wrong variable is a very easy mistake, the key
value itself is sniffed: a value in GROQ_API_KEY that is not a "gsk_" key is
treated as a Gemini key rather than failing with a bare 401. Set LLM_PROVIDER
to "gemini" or "groq" to override the detection entirely.

Nothing here raises. Every failure returns (None, reason) and the caller keeps
its deterministic fallback, so a missing key or a dead network degrades the
wording of a report and never the detection itself.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple

# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = PROJECT_ROOT / ".env"


def load_env(env_path: Optional[Path] = None) -> None:
    """Load API keys from the project .env file.

    Uses python-dotenv when installed, otherwise a tiny KEY=VALUE parser so the
    agents work with no extra dependency. Values already set in the real
    environment always win. Lives here, and runs on import, so provider
    detection cannot depend on which agent happened to be imported first.
    """
    path = Path(env_path or ENV_PATH)
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass

    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lstrip("﻿")
        if key.lower().startswith("export "):
            key = key[7:].strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_env()


DEFAULT_TIMEOUT = 20

# Chosen by measurement, not reputation: both are the fastest model on their
# provider that still returns usable prose at this prompt size.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")


def _sniff() -> Tuple[Optional[str], Optional[str]]:
    """Return (provider, api_key) from the environment, or (None, None)."""
    forced = (os.getenv("LLM_PROVIDER") or "").strip().lower()

    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    groq_key = os.getenv("GROQ_API_KEY")

    if forced == "gemini":
        return ("gemini", gemini_key or groq_key) if (gemini_key or groq_key) else (None, None)
    if forced == "groq":
        return ("groq", groq_key or gemini_key) if (groq_key or gemini_key) else (None, None)

    if gemini_key:
        return "gemini", gemini_key
    if groq_key:
        # A real Groq key starts with gsk_. Anything else in this variable is
        # almost certainly a key for another provider pasted by mistake.
        return ("groq" if groq_key.startswith("gsk_") else "gemini"), groq_key
    return None, None


def provider_name() -> Optional[str]:
    return _sniff()[0]


def model_name() -> Optional[str]:
    provider = provider_name()
    return {"gemini": GEMINI_MODEL, "groq": GROQ_MODEL}.get(provider or "")


def is_available() -> bool:
    """True when a key is configured AND its SDK is importable."""
    provider, key = _sniff()
    if not key:
        return False
    try:
        if provider == "gemini":
            import google.genai  # noqa: F401
        else:
            import groq  # noqa: F401
    except ImportError:
        return False
    return True


def describe() -> str:
    """One-line status for CLI output and the dashboard."""
    provider, key = _sniff()
    if not key:
        return "no LLM key configured (deterministic mode)"
    if not is_available():
        return f"{provider} key found but its SDK is not installed (deterministic mode)"
    return f"{provider} · {model_name()}"


# --------------------------------------------------------------------------- #
# Completion
# --------------------------------------------------------------------------- #

def complete(system: str,
             user: str,
             max_tokens: int = 500,
             json_mode: bool = False,
             timeout: int = DEFAULT_TIMEOUT) -> Tuple[Optional[str], str]:
    """Return (text, status). status is "ok" or a short machine-readable reason."""
    provider, key = _sniff()
    if not key:
        return None, "no_api_key"

    try:
        if provider == "gemini":
            return _complete_gemini(system, user, key, max_tokens, json_mode, timeout)
        return _complete_groq(system, user, key, max_tokens, json_mode, timeout)
    except ImportError:
        return None, f"{provider}_sdk_not_installed"
    except Exception as exc:                     # network, quota, auth, bad model
        return None, _classify(exc)


def _classify(exc: Exception) -> str:
    """Turn a provider exception into a reason a human can act on.

    The bare class name is the same for a bad key and a rate limit, which is
    exactly when the difference matters most.
    """
    name = type(exc).__name__
    text = str(exc).lower()
    if "429" in text or "quota" in text or "rate" in text and "limit" in text:
        return "rate_limited"
    if "401" in text or "api key" in text or "unauthorized" in text:
        return "bad_api_key"
    if "404" in text or "not found" in text:
        return "model_not_found"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    return f"error:{name}"


def _complete_gemini(system: str, user: str, key: str, max_tokens: int,
                     json_mode: bool, timeout: int) -> Tuple[Optional[str], str]:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=key,
                          http_options=types.HttpOptions(timeout=timeout * 1000))
    config = types.GenerateContentConfig(
        system_instruction=system,
        temperature=0.2,
        # Recent Gemini models spend part of the output budget on internal
        # reasoning; too small a cap returns a truncated fragment instead of an
        # answer, so leave clear headroom above the prose we actually want.
        max_output_tokens=max_tokens * 3,
        response_mime_type="application/json" if json_mode else "text/plain",
    )
    response = client.models.generate_content(
        model=GEMINI_MODEL, contents=user, config=config)

    text = (response.text or "").strip()
    return (text, "ok") if text else (None, "empty_response")


def _complete_groq(system: str, user: str, key: str, max_tokens: int,
                   json_mode: bool, timeout: int) -> Tuple[Optional[str], str]:
    from groq import Groq

    client = Groq(api_key=key, timeout=timeout, max_retries=2)
    response = client.chat.completions.create(
        model=GROQ_MODEL,
        temperature=0.2,
        max_tokens=max_tokens,
        response_format={"type": "json_object"} if json_mode else None,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
    )
    text = (response.choices[0].message.content or "").strip()
    return (text, "ok") if text else (None, "empty_response")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from agents.investigation_agent import load_env

    load_env()
    print("provider:", describe())
    if is_available():
        text, status = complete(
            "You are a SOC analyst. Answer in one sentence.",
            "41 distinct ports were probed by 192.168.10.50 within 5 minutes.")
        print("status:", status)
        print("text  :", text)
