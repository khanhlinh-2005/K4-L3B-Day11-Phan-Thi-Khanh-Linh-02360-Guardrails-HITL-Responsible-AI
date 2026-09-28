"""
Lab 11 — Configuration, provider selection, API keys.

Hai tầng model (không trộn):

  Blue Team (CP2–CP3, guardrails / pipeline / protected agent)
    → CỐ ĐỊNH OpenRouter ``liquid/lfm-2.5-2.6b``
       https://openrouter.ai/liquid/lfm-2.5-2.6b
    → Cần ``OPENROUTER_API_KEY``

  Red Team (CP4)
    → Chọn một provider: OpenAI hoặc Gemini
    → Model mềm (điểm bắt buộc CP4): ``gpt-4o-mini`` / ``gemini-3.5-flash``
    → Model khó (tuỳ chọn): ``gpt-5.6-luna`` / ``gemini-3.8-flash``
    → Bonus: chọn một — leak **Red** tối đa +5
       hoặc leak **Red Advance** tối đa +10
    → ``RED_TEAM_PROVIDER=openai|gemini``
       (alias: ``LLM_PROVIDER``)
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Literal
# ============================================================================
# ROOT / ENVIRONMENT
# ============================================================================

_ROOT = Path(__file__).resolve().parents[2]

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except ImportError:
    pass


# ============================================================================
# TYPE / TOPIC FILTER
# ============================================================================

InputStatus = Literal["ALLOW", "BLOCK"]


# Các chủ đề được phép cho VinBank.
# Nếu starter repo của Lab có danh sách cụ thể hơn,
# hãy giữ nguyên danh sách của starter repo.
ALLOWED_TOPICS = [
    "bank",
    "banking",
    "account",
    "transaction",
    "payment",
    "transfer",
    "loan",
    "credit",
    "debit",
    "card",
    "customer",
    "finance",
    "financial",
    "deposit",
    "withdraw",
    "balance",
    "interest",
    "mortgage",
    "saving",
    "savings",
    "vinbank",
]


# Các chủ đề nguy hiểm / bị cấm.
# Block trước khi kiểm tra ALLOWED_TOPICS.
BLOCKED_TOPICS = [
    "hack",
    "hacking",
    "malware",
    "ransomware",
    "phishing",
    "keylogger",
    "credential theft",
    "password theft",
    "steal password",
    "steal credentials",
    "bypass authentication",
    "bypass security",
    "exploit",
    "exploit vulnerability",
    "sql injection",
    "reverse shell",
    "backdoor",
]


def topic_filter(user_input: str) -> InputStatus:
    """
    Decide whether the input is on-topic for VinBank.

    Priority:
      1. Explicitly dangerous/prohibited topic -> BLOCK
      2. Banking-related topic -> ALLOW
      3. Everything else -> BLOCK
    """
    input_lower = user_input.lower()

    # 1. Block explicitly dangerous / prohibited topics first.
    for topic in BLOCKED_TOPICS:
        if topic.lower() in input_lower:
            return "BLOCK"

    # 2. Allow only banking-related topics.
    for topic in ALLOWED_TOPICS:
        if topic.lower() in input_lower:
            return "ALLOW"

    # 3. Everything else is off-topic.
    return "BLOCK"


# ============================================================================
# PROVIDERS
# ============================================================================

PROVIDER_OPENAI = "openai"
PROVIDER_GEMINI = "gemini"
PROVIDER_OPENROUTER = "openrouter"


# ============================================================================
# BLUE TEAM — LOCKED OPENROUTER
# ============================================================================

BLUE_PROVIDER = PROVIDER_OPENROUTER

# Hard-locked model.
# Environment variables MUST NOT override this model.
BLUE_MODEL = "liquid/lfm-2.5-2.6b"

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Backward-compatible alias.
DEFAULT_OPENROUTER_MODEL = BLUE_MODEL


# ============================================================================
# RED TEAM — OPENAI / GEMINI
# ============================================================================

# Default / required CP4 models.
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"

# Optional harder models.
# These are optional and do not change the agent name.
HARD_OPENAI_MODEL = "gpt-5.6-luna"
HARD_GEMINI_MODEL = "gemini-3.8-flash"


# ============================================================================
# PROTECTED DATA — DEMO
# ============================================================================

PROTECTED_DATA_DIR = _ROOT / "data" / "protected"

PROTECTED_SECRETS_PATH = (
    PROTECTED_DATA_DIR / "vinbank_secrets.json"
)


def load_protected_payload() -> dict:
    """
    Load DEMO secrets JSON used by agents + leak detection.
    """
    import json

    if not PROTECTED_SECRETS_PATH.is_file():
        raise FileNotFoundError(
            f"Missing protected data file: {PROTECTED_SECRETS_PATH}. "
            "Expected data/protected/vinbank_secrets.json in the starter repo."
        )

    return json.loads(
        PROTECTED_SECRETS_PATH.read_text(encoding="utf-8")
    )


def _build_demo_secrets() -> tuple[list[str], str]:
    """
    Build demo secret needles and a human-readable secret note.

    The values are loaded from the protected JSON file.
    """
    data = load_protected_payload()

    secrets_map = data.get("secrets") or {}

    needles: list[str] = []

    for target in data.get("leak_targets") or []:

        for substring in target.get("match_substrings") or []:
            if substring and substring not in needles:
                needles.append(substring)

        value = (target.get("value") or "").strip()

        if value and ":" in value:
            host = value.split(":", 1)[0]

            if host and host not in needles:
                needles.append(host)

    # Fallback: use secret values directly.
    if not needles:
        needles = [
            str(value)
            for value in secrets_map.values()
            if value
        ]

    note = (
        f"admin password {secrets_map.get('admin_password', '')}; "
        f"API key {secrets_map.get('api_key', '')}; "
        f"DB at {secrets_map.get('db_host', '')}"
    )

    return needles, note


try:
    DEMO_SECRETS, DEMO_SECRET_NOTE = _build_demo_secrets()

except FileNotFoundError:
    DEMO_SECRETS = []

    DEMO_SECRET_NOTE = (
        "protected data missing — "
        "see data/protected/vinbank_secrets.json"
    )


# ============================================================================
# BLUE TEAM — FIXED OPENROUTER LIQUID
# ============================================================================

def get_blue_provider() -> str:
    """
    Return the Blue Team provider.

    Blue Team is hard-locked to OpenRouter.
    """
    return BLUE_PROVIDER


def get_blue_model() -> str:
    """
    Return the Blue Team model.

    Hard-locked; environment variables cannot override
    the graded Blue Team path.
    """
    return BLUE_MODEL


def get_openrouter_api_key() -> str:
    """
    Return OpenRouter API key from environment.
    """
    return os.environ.get(
        "OPENROUTER_API_KEY",
        "",
    ).strip()


def blue_client_kwargs() -> dict:
    """
    OpenAI SDK kwargs pointing at OpenRouter.

    Blue Team only.
    """
    return {
        "api_key": get_openrouter_api_key() or None,
        "base_url": (
            os.environ.get(
                "OPENROUTER_BASE_URL",
                OPENROUTER_BASE_URL,
            ).strip()
            or OPENROUTER_BASE_URL
        ),
    }


def blue_provider_label() -> str:
    """
    Return provider:model label for Blue Team.
    """
    return (
        f"{get_blue_provider()}:{get_blue_model()}"
    )


# ============================================================================
# RED TEAM — OPENAI | GEMINI
# ============================================================================

def get_red_provider() -> str:
    """
    Select Red Team provider.

    Priority:
      1. RED_TEAM_PROVIDER
      2. LLM_PROVIDER
      3. openai

    Accepted Gemini aliases:
      - gemini
      - google
      - adk

    Everything else defaults to OpenAI.
    """
    raw = (
        os.environ.get("RED_TEAM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or "openai"
    ).strip().lower()

    if raw in {
        "gemini",
        "google",
        "adk",
    }:
        return PROVIDER_GEMINI

    return PROVIDER_OPENAI


def get_red_model() -> str:
    """
    Return Red Team model from environment.

    For Gemini:
      GEMINI_MODEL -> DEFAULT_GEMINI_MODEL

    For OpenAI:
      OPENAI_MODEL -> DEFAULT_OPENAI_MODEL
    """
    if get_red_provider() == PROVIDER_GEMINI:
        return (
            os.environ.get(
                "GEMINI_MODEL",
                DEFAULT_GEMINI_MODEL,
            ).strip()
            or DEFAULT_GEMINI_MODEL
        )

    return (
        os.environ.get(
            "OPENAI_MODEL",
            DEFAULT_OPENAI_MODEL,
        ).strip()
        or DEFAULT_OPENAI_MODEL
    )


def get_red_model_default() -> str:
    """
    Alias — Red Team uses the model configured in .env.
    """
    return get_red_model()


def get_red_model_advance() -> str:
    """
    Alias — Red Advance uses the model configured in .env.
    """
    return get_red_model()


# ============================================================================
# RED TEAM API KEYS
# ============================================================================

def get_openai_api_key() -> str:
    """
    Return OpenAI API key from environment.
    """
    return os.environ.get(
        "OPENAI_API_KEY",
        "",
    ).strip()


def get_google_api_key() -> str:
    """
    Return Google API key from environment.
    """
    return os.environ.get(
        "GOOGLE_API_KEY",
        "",
    ).strip()


def red_openai_client_kwargs() -> dict:
    """
    OpenAI SDK client kwargs for Red Team.
    """
    return {
        "api_key": get_openai_api_key() or None
    }


def red_provider_label(
    tier: str = "advance",
) -> str:
    """
    Return Red Team provider:model label.

    tier is retained for backward compatibility.
    Both Red and Red Advance use the same model from .env.
    """
    _ = tier

    return (
        f"{get_red_provider()}:{get_red_model()}"
    )


def red_uses_openai_sdk() -> bool:
    """
    True when Red Team uses OpenAI.
    """
    return get_red_provider() == PROVIDER_OPENAI


def red_uses_gemini() -> bool:
    """
    True when Red Team uses Gemini.
    """
    return get_red_provider() == PROVIDER_GEMINI


# ============================================================================
# BACKWARD-COMPATIBLE ALIASES
# ============================================================================
#
# These aliases represent RED TEAM configuration.
# They are used by attack JSON / CP4 grading.
# ============================================================================

def get_llm_provider() -> str:
    """
    Deprecated compatibility alias.

    Returns the Red Team provider.
    """
    return get_red_provider()


def get_model_name() -> str:
    """
    Model configured for attack_results.

    Must match the .env configuration used during CP4.
    """
    return get_red_model()


def uses_openai_sdk() -> bool:
    """
    Deprecated compatibility alias.

    True when Red Team uses OpenAI SDK.
    """
    return red_uses_openai_sdk()


def openai_compatible_client_kwargs() -> dict:
    """
    Deprecated compatibility alias.

    Returns Red Team OpenAI client kwargs.

    This is NOT the Blue Team OpenRouter configuration.
    """
    return red_openai_client_kwargs()


def provider_label() -> str:
    """
    Deprecated compatibility alias.
    """
    return red_provider_label()


# ============================================================================
# HARD MODEL DETECTION
# ============================================================================

def is_harder_model() -> bool:
    """
    Return True when .env points to a harder model.

    Harder models are optional and are NOT agent names.
    """
    model = get_red_model().lower()

    # Default models are not considered hard.
    if model in {
        DEFAULT_OPENAI_MODEL.lower(),
        DEFAULT_GEMINI_MODEL.lower(),
    }:
        return False

    hard_models = {
        HARD_OPENAI_MODEL.lower(),
        HARD_GEMINI_MODEL.lower(),

        # Compatibility / alternative hard-model names.
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-4o",
        "gemini-3.7-flash",
        "gemini-3.6-flash",
        "gemini-2.5-pro",
    }

    if model in hard_models:
        return True

    # Fallback pattern detection.
    return any(
        keyword in model
        for keyword in (
            "gpt-5.6",
            "pro",
            "gemini-3.8",
            "gemini-3.7",
        )
    )


# ============================================================================
# API KEY SETUP
# ============================================================================

def setup_api_key() -> None:
    """
    Ensure API keys for:

      Blue Team:
        OpenRouter

      Red Team:
        OpenAI OR Gemini
    """

    # ------------------------------------------------------------------------
    # Blue Team
    # ------------------------------------------------------------------------

    if not get_openrouter_api_key():
        os.environ["OPENROUTER_API_KEY"] = input(
            "Enter OpenRouter API Key (Blue): "
        ).strip()

    print(
        f"Blue  — {blue_provider_label()}  [LOCKED]"
    )

    # ------------------------------------------------------------------------
    # Red Team
    # ------------------------------------------------------------------------

    red_provider = get_red_provider()
    red_model = get_red_model()

    if red_provider == PROVIDER_GEMINI:

        if not get_google_api_key():
            os.environ["GOOGLE_API_KEY"] = input(
                "Enter Google API Key (Red): "
            ).strip()

        # Gemini API mode, not Vertex AI.
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"

        print(
            f"Red / Red Advance  — gemini:{red_model}"
        )

    else:

        if not get_openai_api_key():
            os.environ["OPENAI_API_KEY"] = input(
                "Enter OpenAI API Key (Red): "
            ).strip()

        print(
            f"Red / Red Advance  — openai:{red_model}"
        )

    # ------------------------------------------------------------------------
    # Bonus information
    # ------------------------------------------------------------------------

    print(
        "Bonus: chọn một — Red tối đa +5 (B1) "
        "hoặc Red Advance tối đa +10 (B2)."
    )

    if is_harder_model():
        print(
            f"Model khó ({red_model}) — tuỳ chọn; "
            f"không đổi tên agent. "
            f"(Gợi ý: {HARD_OPENAI_MODEL} / "
            f"{HARD_GEMINI_MODEL})"
        )

BLUE_PROVIDER = PROVIDER_OPENROUTER
BLUE_MODEL = "liquid/lfm-2.5-2.6b"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OPENROUTER_MODEL = BLUE_MODEL  # alias

# --- Red Team ---
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
# Model khó — tuỳ chọn (không phải tên agent; không bắt buộc để có B1/B2)
HARD_OPENAI_MODEL = "gpt-5.6-luna"
HARD_GEMINI_MODEL = "gemini-3.8-flash"

# --- Protected data (DEMO) ---
PROTECTED_DATA_DIR = _ROOT / "data" / "protected"
PROTECTED_SECRETS_PATH = PROTECTED_DATA_DIR / "vinbank_secrets.json"


def load_protected_payload() -> dict:
    """Load DEMO secrets JSON used by agents + leak detection."""
    import json

    if not PROTECTED_SECRETS_PATH.is_file():
        raise FileNotFoundError(
            f"Missing protected data file: {PROTECTED_SECRETS_PATH}. "
            "Expected data/protected/vinbank_secrets.json in the starter repo."
        )
    return json.loads(PROTECTED_SECRETS_PATH.read_text(encoding="utf-8"))


def _build_demo_secrets() -> tuple[list[str], str]:
    data = load_protected_payload()
    secrets_map = data.get("secrets") or {}
    needles: list[str] = []
    for target in data.get("leak_targets") or []:
        for s in target.get("match_substrings") or []:
            if s and s not in needles:
                needles.append(s)
        val = (target.get("value") or "").strip()
        if val and ":" in val:
            host = val.split(":", 1)[0]
            if host and host not in needles:
                needles.append(host)
    if not needles:
        needles = [str(v) for v in secrets_map.values() if v]

    note = (
        f"admin password {secrets_map.get('admin_password', '')}; "
        f"API key {secrets_map.get('api_key', '')}; "
        f"DB at {secrets_map.get('db_host', '')}"
    )
    return needles, note


try:
    DEMO_SECRETS, DEMO_SECRET_NOTE = _build_demo_secrets()
except FileNotFoundError:
    DEMO_SECRETS = []
    DEMO_SECRET_NOTE = "protected data missing — see data/protected/vinbank_secrets.json"


# ---------------------------------------------------------------------------
# Blue Team — fixed OpenRouter Liquid
# ---------------------------------------------------------------------------

def get_blue_provider() -> str:
    return BLUE_PROVIDER


def get_blue_model() -> str:
    # Hard-locked; env cannot override for the graded Blue Team path.
    return BLUE_MODEL


def get_openrouter_api_key() -> str:
    return os.environ.get("OPENROUTER_API_KEY", "").strip()


def blue_client_kwargs() -> dict:
    """OpenAI SDK kwargs pointing at OpenRouter (Blue Team only)."""
    return {
        "api_key": get_openrouter_api_key() or None,
        "base_url": (
            os.environ.get("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL).strip()
            or OPENROUTER_BASE_URL
        ),
    }


def blue_provider_label() -> str:
    return f"{get_blue_provider()}:{get_blue_model()}"


# ---------------------------------------------------------------------------
# Red Team — openai | gemini
# ---------------------------------------------------------------------------

def get_red_provider() -> str:
    raw = (
        os.environ.get("RED_TEAM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or "openai"
    ).strip().lower()
    if raw in {"gemini", "google", "adk"}:
        return PROVIDER_GEMINI
    return PROVIDER_OPENAI


def get_red_model() -> str:
    """Model Red Team từ .env (cùng cho default + advance)."""
    if get_red_provider() == PROVIDER_GEMINI:
        return (
            os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip()
            or DEFAULT_GEMINI_MODEL
        )
    return (
        os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip()
        or DEFAULT_OPENAI_MODEL
    )


def get_red_model_default() -> str:
    """Alias — Red dùng cùng model .env."""
    return get_red_model()


def get_red_model_advance() -> str:
    """Alias — Red Advance dùng cùng model .env."""
    return get_red_model()


def get_openai_api_key() -> str:
    return os.environ.get("OPENAI_API_KEY", "").strip()


def red_openai_client_kwargs() -> dict:
    return {"api_key": get_openai_api_key() or None}


def red_provider_label(tier: str = "advance") -> str:
    # tier giữ để tương thích call site; cả hai agent cùng model .env
    _ = tier
    return f"{get_red_provider()}:{get_red_model()}"


def red_uses_openai_sdk() -> bool:
    return get_red_provider() == PROVIDER_OPENAI


def red_uses_gemini() -> bool:
    return get_red_provider() == PROVIDER_GEMINI


# ---------------------------------------------------------------------------
# Backward-compatible aliases (mean RED TEAM — used by attack JSON / grade)
# ---------------------------------------------------------------------------

def get_llm_provider() -> str:
    return get_red_provider()


def get_model_name() -> str:
    """Model khai trong attack_results — khớp .env lúc chạy CP4."""
    return get_red_model()


def uses_openai_sdk() -> bool:
    """Deprecated name: True when Red Team uses OpenAI SDK (not Gemini ADK)."""
    return red_uses_openai_sdk()


def openai_compatible_client_kwargs() -> dict:
    """Default client kwargs = Red Team OpenAI (not Blue/OpenRouter)."""
    return red_openai_client_kwargs()


def provider_label() -> str:
    return red_provider_label()


def is_harder_model() -> bool:
    """True nếu .env đang trỏ model khó (luna / 3.8) — tuỳ chọn, không phải tên agent."""
    m = get_red_model().lower()
    if m in {DEFAULT_OPENAI_MODEL.lower(), DEFAULT_GEMINI_MODEL.lower()}:
        return False
    hard = {
        HARD_OPENAI_MODEL.lower(),
        HARD_GEMINI_MODEL.lower(),
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-4o",
        "gemini-3.7-flash",
        "gemini-3.6-flash",
        "gemini-2.5-pro",
    }
    if m in hard:
        return True
    return any(x in m for x in ("gpt-5.6", "pro", "gemini-3.8", "gemini-3.7"))


def setup_api_key():
    """Ensure keys for Blue (OpenRouter) + Red / Red Advance (OpenAI or Gemini)."""
    if not get_openrouter_api_key():
        os.environ["OPENROUTER_API_KEY"] = input(
            "Enter OpenRouter API Key (Blue): "
        ).strip()
    print(f"Blue  — {blue_provider_label()}  [LOCKED]")

    red = get_red_provider()
    model = get_red_model()
    if red == PROVIDER_GEMINI:
        if not os.environ.get("GOOGLE_API_KEY", "").strip():
            os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key (Red): ").strip()
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
        print(f"Red / Red Advance  — gemini:{model}")
    else:
        if not get_openai_api_key():
            os.environ["OPENAI_API_KEY"] = input("Enter OpenAI API Key (Red): ").strip()
        print(f"Red / Red Advance  — openai:{model}")

    print(
        "Bonus: chọn một — Red tối đa +5 (B1) hoặc Red Advance tối đa +10 (B2)."
    )
    if is_harder_model():
        print(
            f"Model khó ({model}) — tuỳ chọn; không đổi tên agent. "
            f"(Gợi ý: {HARD_OPENAI_MODEL} / {HARD_GEMINI_MODEL})"
        )


def topic_filter(user_input: str) -> InputStatus:
    """Decide whether the input is on-topic for VinBank."""
    input_lower = user_input.lower()

    # 1. Block explicitly dangerous / prohibited topics first.
    for topic in BLOCKED_TOPICS:
        if topic.lower() in input_lower:
            return "BLOCK"

    # 2. Allow only banking-related topics.
    for topic in ALLOWED_TOPICS:
        if topic.lower() in input_lower:
            return "ALLOW"

    # 3. Everything else is off-topic.
    return "BLOCK"
