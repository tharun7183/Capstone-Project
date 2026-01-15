
# ---- constants.py (compatible with latest.py & your split) ----
import os

# If you use Colab, try pulling OPENAI_API_KEY from its secrets too
def _detect_colab() -> bool:
    try:
        import google.colab
        from google.colab import _ipython
        ip = _ipython.get_ipython()
        return bool(ip and getattr(ip, "kernel", None))
    except Exception:
        return False

_COLAB = _detect_colab()
try:
    from google.colab import userdata as _colab_userdata
except Exception:
    _colab_userdata = None

def _get_openai_key():
    k = os.getenv("OPENAI_API_KEY")
    if k:
        return k
    if _COLAB and _colab_userdata:
        try:
            return _colab_userdata.get("OPENAI_API_KEY")
        except Exception:
            return None
    return None

# Model name used by latest.py
OPENAI_MODEL = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"

# Feature flags exactly as in latest.py
SEND_SECRETS_TO_OPENAI   = False
STRICT_NO_LLM_ON_SECRETS = True
PRIVACY_STRICT           = True

# Optional: allow forcing LLM off from env (useful in Colab to avoid hangs)
DISABLE_LLM = os.getenv("DISABLE_LLM", "0") == "1"
