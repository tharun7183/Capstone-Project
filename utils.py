# utils.py
from __future__ import annotations
from typing import Any, Iterable, Optional, Tuple, List, Dict, Set
from constants import OPENAI_MODEL, SEND_SECRETS_TO_OPENAI, STRICT_NO_LLM_ON_SECRETS, PRIVACY_STRICT

import os, json, re, io, uuid, ipaddress, datetime, getpass, sys, pathlib
from typing import Any, Iterable, Optional, Tuple, List, Dict, Set
from urllib.parse import urlparse, parse_qs, unquote, urlsplit, urlunsplit, quote

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

from openai import OpenAI

_OPENAI_KEY = _get_openai_key()

def _get_openai_client():
    try:
        return OpenAI(api_key=_OPENAI_KEY) if _OPENAI_KEY else None
    except Exception:
        return None

client = _get_openai_client()
def _have_llm():
    try:
        return client is not None
    except NameError:
        return False



# Paths & Avro schemas
SAVE_DIR = os.getenv("SAVE_DIR", "/content/json_data")
SCHEMA_DIR = pathlib.Path(os.getenv("SCHEMA_DIR", "/content"))

SCHEMA_PATHS = {
    "dbconn": SCHEMA_DIR / "database_connection_schema.avsc",
    "cloudconn": SCHEMA_DIR / "cloud_connection_schema.avsc",
    "creating": SCHEMA_DIR / "create_dag_schema.avsc",
    "trigger": SCHEMA_DIR / "trigger_dag_schema.avsc",
    "delete_conn": SCHEMA_DIR / "delete_connection_schema.avsc",
    "delete_dag": SCHEMA_DIR / "delete_dag_schema.avsc",
}
RAW_SCHEMAS: Dict[str, dict] = {
    k: json.load(open(str(p))) for k, p in SCHEMA_PATHS.items() if p.exists()
}

from avro.schema import parse as avro_parse
try:
    from avro.io import validate as avro_validate
    _AVRO_HAS_VALIDATE = True
except Exception:
    from avro.io import DatumWriter, BinaryEncoder
    _AVRO_HAS_VALIDATE = False
try:
    from avro.errors import AvroTypeException
except Exception:
    try:
        from avro.io import AvroTypeException
    except Exception:
        class AvroTypeException(Exception): ...

SCHEMAS = {k: avro_parse(json.dumps(v)) for k, v in RAW_SCHEMAS.items()}


_SECRET_KEY_ALIASES = {
    "host":"host","hostname":"host","server":"host",
    "port":"port",
    "user":"login","username":"login","login":"login","uid":"login",
    "password":"password","pass":"password","pwd":"password",
    "database":"database","db":"database","dbname":"database",
    "connection_string":"connection_string","conn_string":"connection_string","dsn":"connection_string",
    "region":"region_name","region_name":"region_name",
    "bucket":"bucket_name","bucket_name":"bucket_name",
    "container":"container_name","container_name":"container_name",
    "securitytoken":"securityToken","security_token":"securityToken",
    "aws_access_key_id":"aws_access_key_id",
    "aws_secret_access_key":"aws_secret_access_key",
    "key_json":"key_json",
}

_SIDE_HINTS = {
    "source": ("source", None), "src": ("source", None),
    "source_db": ("source", "db"),
    "source.cloud": ("source", "cloud"), "source_cloud": ("source", "cloud"),
    "destination": ("dest", None), "dest": ("dest", None),
    "dest_db": ("dest", "db"), "destination_db": ("dest", "db"),
    "dest.cloud": ("dest", "cloud"), "dest_cloud": ("dest", "cloud"),
}

def _canon_secret_key_public(k: str) -> str:
    k = (k or "").strip().lower().replace(" ", "_")
    return _SECRET_KEY_ALIASES.get(k, k)

def parse_inline_secrets(text: str) -> Tuple[str, Dict[str, Dict[str, str]], bool]:
    
    original = text or ""
    kept = original
    captured = False
    buckets: Dict[str, Dict[str, str]] = {
        "source_db": {}, "dest_db": {}, "source_cloud": {}, "dest_cloud": {}
    }

    url_pat = re.compile(
        r'(?:(source|src|destination|dest)[^:=]{0,30}[:=]\s*)?'
        r'((?:[a-z][a-z0-9+\-.]*)://[^\s;,]+)',
        re.I
    )
    for m in url_pat.finditer(original):
        side_hint = (m.group(1) or "").lower()
        url = m.group(2).strip().rstrip('.,;)')
        scheme = url.split("://", 1)[0].lower()

        if scheme in ("postgres","postgresql","psql","mysql","mariadb","mssql","sqlserver","oracle"):
            kind = "db"
        elif scheme in ("s3","gs","abfss","wasbs"):
            kind = "cloud"
        else:
            kind = "db"

        side = "source"
        if "dest" in side_hint or "destination" in side_hint:
            side = "dest"
        elif "src" in side_hint or "source" in side_hint:
            side = "source"

        buckets[f"{side}_{kind}"]["connection_string"] = url
        kept = kept.replace(m.group(0), "")
        captured = True

    pair_pat = re.compile(
        r'(?:(?P<prefix>source|src|source_db|source\.cloud|source_cloud|destination|dest|dest_db|destination_db|dest\.cloud|dest_cloud)[\s\._-]*)?'
        r'(?P<key>connection[_\s-]?string|host|hostname|server|port|user(?:name)?|login|uid|password|pass|pwd|database|db|dbname|region(?:[_\s-]?name)?|bucket(?:_name)?|container(?:_name)?|security[_-]?token|aws_access_key_id|aws_secret_access_key|key_json)'
        r'\s*[:=]\s*'
        r'(?P<val>[^;,\n]+)',
        re.I
    )

    for m in pair_pat.finditer(original):
        prefix = (m.group("prefix") or "").lower().replace(" ", "_")
        key = _canon_secret_key_public(m.group("key"))
        val = (m.group("val") or "").strip().strip('\'"').rstrip('.,)')

        side, kind = None, None
        if prefix in _SIDE_HINTS:
            side, kind = _SIDE_HINTS[prefix]

        if not kind:
            kind = "cloud" if key in (
                "region_name","bucket_name","container_name",
                "aws_access_key_id","aws_secret_access_key","key_json","securityToken"
            ) else "db"
        if not side:
            side = "source" if ("src" in prefix or "source" in prefix) else ("dest" if "dest" in prefix else "source")

        if key == "port":
            val = re.sub(r'\D', '', val)

        buckets[f"{side}_{kind}"][key] = val
        kept = kept.replace(m.group(0), "")
        captured = True

    kept = re.sub(r'\s{2,}', ' ', kept).strip()
    return kept, buckets, captured

def _save_json_file(path: str, obj: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=4)

# Helpers / enums
def debug(*args, **kwargs):
    if os.getenv("BOT_DEBUG") == "1":
        print(*args, **kwargs)

def _assert_no_secrets_payload():
    # No secrets should be present in any payload we send.
    assert not getattr(sys.modules[__name__], "last_llm_payload_contains_secret", False), "safety: secrets must not be sent"
def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from _walk(v)
    elif isinstance(node, list):
        for it in node:
            yield from _walk(it)

def _field_enum_symbols(root_schema: dict, field_name: str) -> Optional[List[str]]:
    for node in _walk(root_schema or {}):
        if node.get("type") == "record" and "fields" in node:
            for fld in node["fields"]:
                if fld.get("name") == field_name:
                    t = fld.get("type")
                    if isinstance(t, dict) and t.get("type") == "enum":
                        return list(t.get("symbols", []))
                    if isinstance(t, list):
                        for m in t:
                            if isinstance(m, dict) and m.get("type") == "enum":
                                return list(m.get("symbols", []))
    return None

def _top_level_fields(schema_key: str) -> List[str]:
    root = RAW_SCHEMAS.get(schema_key)
    if not root:
        return []
    tp = root.get("type")
    if isinstance(tp, dict) and tp.get("type") == "record":
        return [f["name"] for f in tp.get("fields", [])]
    if tp == "record":
        return [f["name"] for f in root.get("fields", [])]
    if isinstance(tp, list):
        for m in tp:
            if isinstance(m, dict) and m.get("type") == "record":
                return [f["name"] for f in m.get("fields", [])]
    return []

def _prune_to_schema_fields(schema_key: str, data: dict) -> dict:
    if not data:
        return data
    allowed = set(_top_level_fields(schema_key))
    if not allowed:
        return data
    return {k: v for k, v in data.items() if k in allowed}

def _secrets_valid_db(sec: Optional[dict]) -> bool:
    if not sec: return False
    try:
        validate_host(sec.get("host"))
        validate_port(sec.get("port"))
        validate_non_empty("login", sec.get("login"))
        validate_non_empty("password", sec.get("password"))
        return True
    except Exception:
        return False

CONN_SCHEMES = r'(?:mysql(?:\+\w+)?|postgres(?:ql)?(?:\+\w+)?|pg|mssql(?:\+\w+)?|sqlserver|oracle(?:\+\w+)?|jdbc:[^ \t\n]+|redshift|snowflake)'
CLOUD_SCHEMES = r'(?:s3|gs|gcs|abfss|wasbs|azure)'
CONN_URL_RE  = re.compile(rf'(?i)\b(?:{CONN_SCHEMES})://[^\s]+')
CLOUD_URL_RE = re.compile(rf'(?i)\b(?:{CLOUD_SCHEMES})://[^\s]+')

KV_KEYS = r'(?:connection_string|host|hostname|server|addr|address|port|login|user(?:name)?|pwd|pass(?:word)?|' \
          r'database|db(?:name)?|service_name|sid|schema|table|bucket(?:_name)?|container_name|object(?:_name)?|' \
          r'region_name|access_key_id|aws_access_key_id|secret_access_key|aws_secret_access_key|' \
          r'key_json|sas_token|securitytoken|api[_-]?key)'
KV_RE = re.compile(rf'(?i)\b({KV_KEYS})\s*[:=]\s*([^\s;,]+)')

SECRET_KV_RE = re.compile(r'(?i)\b(password|pwd|pass|aws_secret_access_key|securitytoken|api[_-]?key|secret)\s*[:=]\s*([^\s;,]+)')
URL_CRED_RE  = re.compile(r'(\w[\w+.-]*://[^:@\s]+:)([^@/\s]+)(@)')


def _redact_for_llm(text: str) -> tuple[str, bool]:
    if not text:
        return text, False
    red, hit = text, False

    def _kv_secret_sub(m):
        nonlocal hit
        hit = True
        return f"{m.group(1)}=<redacted>"
    red = re.sub(SECRET_KV_RE, _kv_secret_sub, red)

    def _url_cred_sub(m):
        nonlocal hit
        hit = True
        return m.group(1) + "<redacted>" + m.group(3)
    red = re.sub(URL_CRED_RE, _url_cred_sub, red)

    def _url_sub(m):
        nonlocal hit
        hit = True
        return "<redacted-url>"
    red = re.sub(CONN_URL_RE, _url_sub, red)
    red = re.sub(CLOUD_URL_RE, _url_sub, red)

    def _kv_sub(m):
        nonlocal hit
        hit = True
        return f"{m.group(1)}=<redacted>"
    red = re.sub(KV_RE, _kv_sub, red)

    return red, hit

DB_TYPES_CANON = {"MYSQL", "PSQL", "MSSQL", "ORACLE"}
CLOUD_DB_TYPES = {"AWS_RDS", "AMAZON_AURORA", "GCP_CLOUD_SQL"}
ALL_TYPES_CANON = DB_TYPES_CANON | CLOUD_DB_TYPES
CLOUD_CONN_TYPES: Set[str] = set(
    _field_enum_symbols(RAW_SCHEMAS.get("cloudconn", {}), "conn_type") or []
)
CLOUD_OPTIONAL_FIELDS = [
    "connection_string","aws_access_key_id","aws_secret_access_key","region_name",
    "container_name","bucket_name","key_json","login","password","securityToken",
]

def _cloud_requirement_groups(conn_type_text: Optional[str]) -> List[List[str]]:

    t = (conn_type_text or "").lower()
    # AWS S3-like
    if ("s3" in t) or ("aws" in t):
        return [
            ["connection_string"],
            ["aws_access_key_id", "aws_secret_access_key", "region_name"],
        ]
    # GCP GCS-like
    if ("gs" in t) or ("gcs" in t) or ("google" in t):
        return [
            ["connection_string"],
            ["key_json"],
        ]
    # Azure ADLS/Blob-like
    if ("abfss" in t) or ("wasbs" in t) or ("azure" in t) or ("adls" in t) or ("blob" in t):
        return [
            ["connection_string"],
            ["container_name"],
        ]
    return [["connection_string"]]



_USERINFO_RE = re.compile(r'^(?P<scheme>[^:]+)://(?P<u>[^@]*)@(?P<rest>.*)$')

def _encode_userinfo_if_needed(url: str) -> str:
    m = _USERINFO_RE.match(url)
    if not m:
        return url  # no userinfo section → nothing to fix
    userinfo = m.group("u")
    # If userinfo already looks clean (no reserved chars other than %XX), keep it.
    # We'll conservatively re-encode on any clearly unsafe raw chars.
    if re.search(r'[@:/?#&=+\s]', userinfo):
        # Split only on the FIRST ':' → username : password (password may include :)
        if ':' in userinfo:
            user_raw, pass_raw = userinfo.split(':', 1)
        else:
            user_raw, pass_raw = userinfo, ""
        # Preserve existing % escapes, encode everything else
        user_enc = quote(user_raw, safe='%')
        pass_enc = quote(pass_raw, safe='%')
        fixed = f"{m.group('scheme')}://{user_enc}:{pass_enc}@{m.group('rest')}"
        return fixed
    return url

def _normalized_urlsplit(url: str):
    """
    Try to parse; if parse is ambiguous due to unencoded userinfo, repair and re-parse.
    """
    p = urlsplit(url)
    # If hostname parsed OK, we're done.
    if p.hostname:
        return p
    # Try to fix userinfo and reparse.
    fixed = _encode_userinfo_if_needed(url)
    return urlsplit(fixed)

def _pick_default_port(db_type: str):
    return str(DEFAULT_PORTS.get(db_type.upper(), "")) or None

def validate_db_connection_string(db_type: str, conn_str: str) -> dict:
    """
    Robustly parses DB connection strings with special characters in username/password.
    Always returns decoded ('human') values in: host, port (str), login, password, and
    database/service_name when present. Raises ValueError on clearly invalid inputs.
    """
    if not conn_str or "://" not in conn_str:
        raise ValueError("Connection string must include a scheme like 'postgresql://'.")
    p = _normalized_urlsplit(conn_str)

    host = p.hostname or None
    if not host:
        raise ValueError("host must be an IP or valid hostname")

    # username/password from urlsplit are already percent-decoded
    login = p.username or None
    password = p.password or None

    # port might be None → use default for the db_type if available
    port = p.port
    if port is None:
        port = _pick_default_port(db_type)
    else:
        port = str(port)

    # database / service name from path or query (driver-specific)
    # Strip leading '/'
    path = (p.path or "").lstrip("/")
    query = parse_qs(p.query or "", keep_blank_values=True)

    out = {"host": host, "port": port, "login": login, "password": password}

    dt = (db_type or "").upper()
    if dt in {"MYSQL", "PSQL"}:
        if path:
            out["database"] = path
    elif dt in {"MSSQL"}:
        # SQL Server: DB can be in path or as database= in query params (various casings)
        if path:
            out["database"] = path
        else:
            for k in ("database", "Database", "databaseName"):
                if k in query and query[k]:
                    out["database"] = query[k][0]
                    break
    elif dt in {"ORACLE"}:
        # Treat path as service name for typical cx_Oracle style URIs
        if path:
            out["service_name"] = path

    # Basic sanity checks (reuse your existing validators if you have them)
    # If these exist in your file: validate_host, validate_port, validate_non_empty
    try:
        validate_host(out["host"])
        if out["port"]:
            validate_port(out["port"])
        if out["login"] is not None:
            validate_non_empty("login", out["login"])
        if out["password"] is not None:
            validate_non_empty("password", out["password"])
    except Exception as e:
        # Surface as ValueError so callers can catch and degrade gracefully
        raise ValueError(str(e))

    return out

ACK_TOKENS = {"ok","okay","yes","y","proceed","continue","go","go ahead","confirm","looks good","good to go"}
CANCEL_TOKENS = {"change","edit","modify","back","no"}
DB_LIKE_TYPES = DB_TYPES_CANON | CLOUD_DB_TYPES

# Secret key normalization
SECRET_KEY_ALIASES = {
    "connectionstring": "connection_string",
    "connstring": "connection_string",
    "hostname": "host",
    "username": "login",
    "user": "login",
    "userid": "login",
    "pwd": "password",
    "pass": "password",
}
BLOCK_ALIASES = {
    # DB secrets
    "SOURCE": "source_db","DESTINATION": "dest_db",
    # Cloud secrets
    "source_cloud": "source_cloud", "dest_cloud": "dest_cloud",
}


def _ensure_cloud_keys(d: dict) -> dict:
    for k in CLOUD_OPTIONAL_FIELDS:
        d.setdefault(k, None)
    return d

def _schedules_from(schema_key: str) -> Set[str]:
    got = _field_enum_symbols(RAW_SCHEMAS.get(schema_key, {}), "scheduleInterval") or []
    return set(got)
ALLOWED_SCHEDULES_CREATING = _schedules_from("creating") or {"Daily","Weekly","Monthly","Once"}
ALLOWED_SCHEDULES_TRIGGER  = _schedules_from("trigger")  or {"Daily","Weekly","Monthly","Once","@once"}

_INPUT_ALIASES = {
    "mysql": "MYSQL","psql":"PSQL","my sql": "MYSQL","p sql":"PSQL","postgres":"PSQL","postgresql":"PSQL","post gres":"PSQL","post gresql":"PSQL","pg":"PSQL",
    "sqlserver":"MSSQL","mssql":"MSSQL","mssqlserver":"MSSQL","sql server":"MSSQL","ms sql":"MSSQL","ms sql server":"MSSQL",
    "oracle":"ORACLE","ora":"ORACLE",
    "aws rds":"AWS_RDS","amazon rds":"AWS_RDS","rds":"AWS_RDS",
    "amazon aurora":"AMAZON_AURORA","aurora":"AMAZON_AURORA",
    "gcp cloud sql":"GCP_CLOUD_SQL","cloud sql":"GCP_CLOUD_SQL","google cloud sql":"GCP_CLOUD_SQL","gcp":"GCP_CLOUD_SQL"
}
def _norm_token_strict(s: str) -> str:
    return re.sub(r"[\s_\-]+", "", (s or "")).lower()
def _canonicalize_type(user_text: str) -> Optional[str]:
    t = (user_text or "").strip()
    if not t: return None
    a = _INPUT_ALIASES.get(t.lower())
    if a: return a
    u = t.upper().replace("-", "_").replace(" ", "_")
    if u in ALL_TYPES_CANON: return u
    nt = _norm_token_strict(t)
    for cand in ALL_TYPES_CANON:
        if _norm_token_strict(cand) == nt:
            return cand
    return None

# Validators & parsers

DEFAULT_PORTS = {"MYSQL": 3306, "PSQL": 5432, "MSSQL": 1433, "ORACLE": 1521}
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
COL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DB_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,127}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]{0,63}$")
TABLE_RE = re.compile(r"^[A-Za-z0-9_\.]{1,128}$")
BUCKET_RE = re.compile(r"^(?!.*\.\.)[a-z0-9](?:[a-z0-9.-]{1,61})[a-z0-9]$")

def _v_bucket(name: Optional[str]):
    if name in (None, ""):
        return
    if not BUCKET_RE.fullmatch(name):
        raise ValueError("Bucket: lowercase 3–63, dots/hyphens ok.")

AWS_ACCESS_KEY_ID_RE = re.compile(r"^[A-Z0-9]{20}$")
AWS_SECRET_ACCESS_KEY_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
AWS_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d$")
AZURE_CONTAINER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$")

_MAPPING_OPTOUT_ANY = {"none","no","no columns","no column","no mapping","skip","n/a","na",""}

def _normalize_host_for_validation(h: Optional[str]) -> Optional[str]:
    if not h:
        return h
    if h.startswith("[") and h.endswith("]"):
        return h[1:-1]
    return h

def validate_enum(name: str, value: Optional[str], allowed: Iterable[str]):
    if value is None:
        raise ValueError(f"{name} must be provided")
    if value not in allowed:
        raise ValueError(f"{name} must be one of {sorted(set(allowed))}; got '{value}'")

def validate_non_empty(name: str, value: Any):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")

def validate_port(port_val: Any):
    s = "" if port_val is None else str(port_val)
    if s == "": return
    if s != s.strip() or any(ch.isspace() for ch in s):
        raise ValueError("port must not contain whitespace")
    if not s.isdigit():
        raise ValueError("port must contain only digits")
    p = int(s)
    if not (1 <= p <= 65535):
        raise ValueError("port must be in range 1..65535")

def validate_host(host: Any):
    if not isinstance(host, str) or host == "":
        raise ValueError("host must be a non-empty string")
    if host != host.strip() or any(c.isspace() for c in host):
        raise ValueError("host must not contain whitespace")
    h = _normalize_host_for_validation(host)

    if (h or "").lower() == "localhost":
        return
    try:
        ipaddress.ip_address(h); return
    except ValueError:
        pass
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h or ""):
        raise ValueError("host must be a valid IP or hostname (invalid IPv4 address)")
    if not _HOSTNAME_RE.fullmatch(h or ""):
        raise ValueError("host must be an IP or valid hostname")

# DB URL validation
_DB_SCHEMES = {
    "MYSQL": {"mysql","mysql+pymysql","mysql+mysqldb"},
    "PSQL": {"postgres","postgresql","postgres+psycopg2","postgresql+psycopg2"},
    "MSSQL": {"mssql","mssql+pyodbc","mssql+pymssql"},
    "ORACLE": {"oracle","oracle+cx_oracle"},
}
def _require(cond: bool, msg: str):
    if not cond: raise ValueError(msg)
def _int_or_none(s: Optional[str]) -> Optional[int]:
    if s is None or s == "": return None
    if not s.isdigit(): raise ValueError("Port must be numeric.")
    p = int(s)
    if not (1 <= p <= 65535): raise ValueError("Port must be in range 1..65535.")
    return p
def _parse_netloc(netloc: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    if "@" in netloc:
        creds, hostport = netloc.split("@", 1)
        if ":" in creds: user, pw = creds.split(":", 1)
        else: user, pw = creds, ""
    else:
        hostport, user, pw = netloc, "", ""
    if ":" in hostport: host, port = hostport.rsplit(":", 1)
    else: host, port = hostport, ""
    return (unquote(user) or None, unquote(pw) or None, host or None, port or None)
'''def validate_db_connection_string(db_type: str, conn_str: str) -> Dict[str, Optional[str]]:
    dbt = (db_type or "").upper()
    _require(dbt in _DB_SCHEMES, f"Unsupported DB type '{db_type}'.")
    _require(isinstance(conn_str, str) and conn_str.strip(), "Connection string must be a non-empty string.")
    u = urlparse(conn_str.strip())
    scheme = (u.scheme or "").lower()
    _require(scheme in _DB_SCHEMES[dbt], f"Scheme '{scheme}' not allowed for {dbt}.")
    user, pw, host, port_s = _parse_netloc(u.netloc or "")
    _require(host, "Missing host in connection string."); validate_host(host)
    port = _int_or_none(port_s) or DEFAULT_PORTS.get(dbt)
    path = (u.path or "").lstrip("/")
    q = {k.lower(): v for k, v in (parse_qs(u.query or "")).items()}
    norm: Dict[str, Optional[str]] = {
        "host": host, "port": str(port) if port is not None else None,
        "login": user, "password": pw, "database": None, "service_name": None,
    }
    if dbt in {"MYSQL","PSQL"}:
        _require(path, f"{dbt} URL must include a database name in the path."); norm["database"] = path
    elif dbt == "MSSQL":
        db = path or (q.get("database", [None])[0]) or (q.get("databasename", [None])[0])
        _require(db, "MSSQL URL must include database (path or ?database=)."); norm["database"] = db
    elif dbt == "ORACLE":
        svc = (q.get("service_name", [None])[0]) or (q.get("servicename", [None])[0])
        if svc: norm["service_name"] = svc
        else: _require(path, "ORACLE URL must include /SID or ?service_name=..."); norm["service_name"] = path
    return norm'''

# Column parsers
def parse_columns_list_allow_none(val: str) -> Optional[List[str]]:
    if val is None: return None
    if val.strip() == "": return []
    parts = [x.strip() for x in val.split(",")]
    out: List[str] = []
    for p in parts:
        if p == "" or p.lower() in {"none","null"}:
            out.append(p); continue
        if not COL_RE.fullmatch(p): return None
        out.append(p)
    return out

def parse_dest_columns_allow_tokens(val: str, n: int) -> Optional[List[str]]:
    if val is None: return None
    t = val.strip().lower()
    if t == "": return ["" for _ in range(n)]
    if t in {"no","none","null","skip"}: return ["none" for _ in range(n)]
    parts = [x.strip() for x in val.split(",")]
    if len(parts) != n: return None
    out: List[str] = []
    for p in parts:
        if p == "": out.append("")
        elif p.lower() in {"none","null"}: out.append("none")
        elif p.lower() == "same": out.append("same")
        else:
            if not COL_RE.fullmatch(p): return None
            out.append(p)
    return out

def parse_transform_pipeline(spec: str) -> List[str]:
    s = (spec or "").strip()
    if not s:
        return []
    if "|" not in s and re.search(r"\bto\b", s, flags=re.IGNORECASE):
        s = re.sub(r"\s*\bto\b\s*", "|", s, flags=re.IGNORECASE)
    return [seg.strip() for seg in s.split("|") if seg.strip()]

def parse_transformations_spec(val: str, n: int) -> Optional[List[List[str]]]:
    if val is None or val.strip() == "" or val.strip().lower() in {"none","null"}:
        return [[] for _ in range(n)]
    segs = [s.strip() for s in val.split(";")]
    if len(segs) < n: segs += [""] * (n - len(segs))
    elif len(segs) > n: return None
    out: List[List[str]] = []
    for seg in segs:
        if seg == "" or seg.lower() in {"none","null"}: out.append([])
        else: out.append(parse_transform_pipeline(seg))
    return out

def _norm_secret_key_public(k: str) -> str:
    k = (k or "").strip().replace("-", "_").lower()
    return SECRET_KEY_ALIASES.get(k, k)

SECRET_SIDE_TOKEN_RE = re.compile(r'(?i)\b(source|src|destination|dest)\b')
SECRET_DOTTED_RE = re.compile(
    r'(?i)\b(source|src|destination|dest)_(db|cloud)\.(\w+)\s*(?:=|:)\s*([^\s,;]+)'
)
SECRET_SIDE_KV_RE = re.compile(
    r'(?i)\b(source|src|destination|dest)\b.*?\b(' + KV_KEYS + r')\s*[:=]\s*([^\s,;]+)'
)

# State

class State:
    def __init__(self):
        self.sourceType=None; self.sourceJobType=None; self.destType=None; self.destinationJobType=None
        self.sourceName=None; self.destName=None
        self.sourceDatabase=None; self.destDatabase=None
        self.tableName=None; self.destTableName=None
        self.sourceObjectName=None; self.sourceBucketName=None
        self.destBucketName=None; self.destObjectName=None
        self.sourceCloudConnType=None; self.destCloudConnType=None
        self.scheduleInterval=None; self.startDate=None
        self.noColumnMap=False
        self.sourceColumns=None; self.destColumns=None; self.transformationsSpec=None

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "sourceType": self.sourceType, "sourceJobType": self.sourceJobType,
            "destType": self.destType, "destinationJobType": self.destinationJobType,
            "sourceName": self.sourceName, "destName": self.destName,
            "sourceDatabase": self.sourceDatabase, "destDatabase": self.destDatabase,
            "tableName": self.tableName, "destTableName": self.destTableName,
            "sourceObjectName": self.sourceObjectName, "sourceBucketName": self.sourceBucketName,
            "destBucketName": self.destBucketName, "destObjectName": self.destObjectName,
            "sourceCloudConnType": self.sourceCloudConnType, "destCloudConnType": self.destCloudConnType,
            "scheduleInterval": self.scheduleInterval, "startDate": self.startDate,
            "noColumnMap": self.noColumnMap, "sourceColumns": self.sourceColumns,
            "destColumns": self.destColumns, "transformationsSpec": self.transformationsSpec,
        }

SENSITIVE_STATE_FIELDS = {
    "sourceDatabase","destDatabase","tableName","destTableName",
    "sourceBucketName","destBucketName","sourceObjectName","destObjectName",
}

def _state_for_llm(st: State) -> Dict[str, Any]:
    sv = _state_view(st)
    known = dict(sv.get("known", {}))
    for k in list(known.keys()):
        if k in SENSITIVE_STATE_FIELDS:
            known[k] = "<redacted>"
    sv["known"] = known
    return sv

# File ingest (json/yaml/properties) & secret split
def _load_any_file(path: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r") as f:
            return json.load(f) or {}
    if ext in {".yaml", ".yml"}:
        try:
            import yaml
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            data = {}
            with open(path, "r") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"): continue
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        data[k.strip()] = v.strip()
            return data
    if ext in {".properties", ".props", ".cfg"}:
        data = {}
        with open(path, "r") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"): continue
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    data[k.strip()] = v.strip()
                elif ":" in ln:
                    k, v = ln.split(":", 1)
                    data[k.strip()] = v.strip()
        return data
    raise ValueError("Unsupported file type. Use .json, .yaml/.yml, or .properties")


_SECRET_BLOCK_NAMES = {"source_db", "dest_db", "source_cloud", "dest_cloud"}
_DB_SECRET_KEYS = {"connection_string","host","port","login","password"}
_CLOUD_SECRET_KEYS = set(CLOUD_OPTIONAL_FIELDS)

def _normalize_key_to_field(k: str) -> Optional[str]:
    canon = FRIENDLY_TO_CANON.get((k or "").strip().lower())
    if canon:
        return canon
    canon = KEY_ALIASES.get(re.sub(r"[\s_\-]+","", str(k)).lower())
    if canon:
        return canon
    return None

_SECRET_KEYS_DB   = {"connection_string", "host", "port", "login", "password"}
_SECRET_KEYS_CLOUD = {
    "connection_string", "aws_access_key_id", "aws_secret_access_key",
    "region_name", "container_name", "bucket_name", "key_json",
    "login", "password", "securityToken",
}

def _load_any_config_file(path: str) -> dict:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "r") as f:
            return json.load(f) or {}
    elif ext in {".yaml", ".yml"}:
        try:
            import yaml
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            data = {}
            import re
            with open(path, "r") as f:
                lines = [ln.rstrip("\n") for ln in f]

            i = 0
            while i < len(lines):
                raw = lines[i]
                ln = raw.strip()
                if not ln or ln.startswith("#"):
                    i += 1
                    continue

                if ":" in ln:
                    key, rest = ln.split(":", 1)
                    key = key.strip()
                    rest = rest.strip()

                    if rest == "":
                        j = i + 1
                        items = []
                        while j < len(lines):
                            nxt = lines[j]
                            if re.match(r"^\s*-\s+.*", nxt):
                                items.append(re.sub(r"^\s*-\s+", "", nxt).strip())
                                j += 1
                                continue
                            if nxt.strip() == "":
                                j += 1
                                continue
                            break
                        if items:
                            data[key] = items
                            i = j
                            continue
                        else:
                            data[key] = ""
                    else:
                        data[key] = rest
                i += 1

            return data
    elif ext in {".properties", ".props", ".cfg"}:
        data = {}
        with open(path, "r") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    data[k.strip()] = v.strip()
                elif ":" in ln:
                    k, v = ln.split(":", 1)
                    data[k.strip()] = v.strip()
        return data
    else:
        raise ValueError("Unsupported file type. Use .json, .yaml/.yml, or .properties")

def _normalize_file_keys_to_internal(raw: dict) -> dict:
    out = {}
    if not isinstance(raw, dict):
        return out

    secret_block_names = { "source_db", "dest_db", "source_cloud", "dest_cloud" }

    for k, v in raw.items():
        if not isinstance(k, str):
            out[k] = v
            continue

        kl = k.strip()
        kl_lower = kl.lower()

        if kl_lower in secret_block_names:
            out[kl_lower] = v
            continue

        if isinstance(v, dict) and _norm_token_strict(kl) in {"sourcedb", "destdb", "sourcecloud", "destcloud"}:
            out[kl_lower] = v
            continue

        canon = FRIENDLY_TO_CANON.get(kl_lower)
        if canon:
            out[canon] = v
            continue

        canon = KEY_ALIASES.get(_norm_token_strict(kl))
        if canon:
            out[canon] = v
        else:
            out[k] = v

    return out

def _file_read_and_split(path: str) -> tuple[dict, dict, list[str]]:

    def _clean_secret(v):
        if v is None: return None
        s = str(v).strip()
        return None if s == "" else s

    def _norm_secret_key(k: str) -> str:
        k = (k or "").strip().replace("-", "_")
        kl = k.lower()
        return SECRET_KEY_ALIASES.get(kl, kl)

    errors: list[str] = []
    raw = _load_any_config_file(path)
    norm = _normalize_file_keys_to_internal(raw)

    non_secret_fields: dict = {}
    for fld in [
        "sourceType","sourceJobType","sourceName","sourceDatabase","tableName",
        "destType","destinationJobType","destName","destDatabase","destTableName",
        "sourceBucketName","sourceObjectName","sourceCloudConnType",
        "destBucketName","destObjectName","destCloudConnType",
        "scheduleInterval","startDate","sourceColumns","destColumns","transformationsSpec",
    ]:
        if fld in norm:
            non_secret_fields[fld] = norm[fld]

    secrets: dict = {
        "source_db":   {},
        "dest_db":     {},
        "source_cloud":{},
        "dest_cloud":  {},
    }
    ingested: set[str] = set()

    def _ingest_db(sec_dict_name: str, payload: dict):
        sd = secrets[sec_dict_name]
        for k, v in (payload or {}).items():
            key = _norm_secret_key(k)
            if key in _SECRET_KEYS_DB:
                sd[key] = _clean_secret(v)
        if "host" in sd and sd["host"] is not None:
            try: validate_host(sd["host"])
            except Exception as e: errors.append(f"{sec_dict_name}: host: {e}")
        if "port" in sd and sd["port"] is not None:
            try: validate_port(sd["port"])
            except Exception as e: errors.append(f"{sec_dict_name}: port: {e}")
        if "login" in sd and sd["login"] is not None:
            try: validate_non_empty("login", sd["login"])
            except Exception as e: errors.append(f"{sec_dict_name}: login: {e}")

    def _ingest_cloud(sec_dict_name: str, payload: dict):
        sd = secrets[sec_dict_name]
        for k, v in (payload or {}).items():
            key = _norm_secret_key(k)
            if key in _SECRET_KEYS_CLOUD:
                sd[key] = _clean_secret(v)
        if "connection_string" in sd and sd["connection_string"] not in (None, ""):
            try: _v_cloud_connstr(sd["connection_string"])
            except Exception as e: errors.append(f"{sec_dict_name}: connection_string: {e}")
        if "bucket_name" in sd and sd["bucket_name"]:
            try: _v_bucket(sd["bucket_name"])
            except Exception as e: errors.append(f"{sec_dict_name}: bucket_name: {e}")

    # dotted keys like source_db.host=..., dest_cloud.bucket_name=...
    for k, v in list(norm.items()):
        if not isinstance(k, str) or "." not in k:
            continue
        left, right = k.split(".", 1)
        left_key = (left or "").strip()
        canon_bucket = BLOCK_ALIASES.get(left_key) or left_key.lower()
        if canon_bucket not in secrets:
            continue
        inner = _norm_secret_key(right)
        keyset = _SECRET_KEYS_DB if canon_bucket.endswith("_db") else _SECRET_KEYS_CLOUD
        if inner in keyset:
            secrets[canon_bucket][inner] = _clean_secret(v)
            norm.pop(k, None)

    # prefixed keys like source_host=..., dest_password=...
    prefix_to_bucket = {"source_": "source_db", "dest_": "dest_db"}
    for pref, bucket in prefix_to_bucket.items():
        for k, v in list(norm.items()):
            if isinstance(k, str) and k.startswith(pref):
                inner = _norm_secret_key(k[len(pref):])
                if inner in _SECRET_KEYS_DB:
                    secrets[bucket][inner] = _clean_secret(v)
                    norm.pop(k, None)

    # exact nested blocks already normalized to source_db/dest_db/source_cloud/dest_cloud
    if isinstance(norm.get("source_db"), dict):   _ingest_db("source_db", norm["source_db"])
    if isinstance(norm.get("dest_db"), dict):     _ingest_db("dest_db", norm["dest_db"])
    if isinstance(norm.get("source_cloud"), dict):_ingest_cloud("source_cloud", norm["source_cloud"])
    if isinstance(norm.get("dest_cloud"), dict):  _ingest_cloud("dest_cloud", norm["dest_cloud"])

    # ALSO accept top-level aliases like "SOURCE", "DESTINATION" etc. (this is the piece that was missing)
    for raw_key in list(norm.keys()):
        if not isinstance(raw_key, str):
            continue
        canon_bucket = BLOCK_ALIASES.get(raw_key) or BLOCK_ALIASES.get((raw_key or "").strip())
        if not canon_bucket:
            continue
        if canon_bucket in ingested:
            continue
        payload = norm.get(raw_key)
        if not isinstance(payload, dict):
            continue
        if canon_bucket.endswith("_db"):
            _ingest_db(canon_bucket, payload)
        else:
            _ingest_cloud(canon_bucket, payload)

    return non_secret_fields, secrets, errors

def _validate_file_fields_and_apply(st: State, fields: Dict[str, Any]) -> List[str]:
    errs: List[str] = []

    _string_expected = {
        "sourceType","sourceJobType","sourceName","sourceDatabase","tableName",
        "destType","destinationJobType","destName","destDatabase","destTableName",
        "sourceBucketName","sourceObjectName","sourceCloudConnType",
        "destBucketName","destObjectName","destCloudConnType",
        "scheduleInterval","startDate",
    }
    for k in list(fields.keys()):
        if k in _string_expected and isinstance(fields[k], dict):
            errs.append(f"{k}: expected a string, got an object (check YAML indentation).")
            fields[k] = ""

    if isinstance(fields.get("sourceColumns"), list):
        fields["sourceColumns"] = ",".join(str(x).strip() for x in fields["sourceColumns"])
    if isinstance(fields.get("destColumns"), list):
        fields["destColumns"] = ",".join(str(x).strip() for x in fields["destColumns"])
    if isinstance(fields.get("transformationsSpec"), list):
        v = fields["transformationsSpec"]
        if v and isinstance(v[0], list):
            fields["transformationsSpec"] = ";".join("|".join(str(s).strip() for s in steps) for steps in v)
        else:
            fields["transformationsSpec"] = ";".join(str(s).strip() for s in v)

    for fld, val in (fields or {}).items():
        if not hasattr(st, fld):
            continue
        new_val, err = try_capture_field(fld, str(val))
        if new_val is None:
            errs.append(f"{fld}: {err or 'Invalid value'}")
            continue
        if fld == "sourceColumns":
            if new_val == "__NO_COLUMN_MAP__":
                st.noColumnMap = True
                st.sourceColumns = st.destColumns = st.transformationsSpec = None
                continue
            else:
                if new_val not in (None, ""):
                    st.noColumnMap = False
        setattr(st, fld, new_val if new_val != "" else None)

    fix = _consistency_or_error(st)
    if fix:
        errs.append(f"columns: {fix}")
    return errs

def _validate_secret_block(st: State, side: str, sec: Dict[str, Optional[str]]) -> List[str]:
    out: List[str] = []
    if not sec:
        return out

    def _add(msg: str): out.append(f"{side}: {msg}")

    if side.endswith("_db"):
        cs = sec.get("connection_string")
        if cs and ((side == "source_db" and st.sourceType) or (side == "dest_db" and st.destType)):
            db_type = st.sourceType if side == "source_db" else st.destType
            try:
                validate_db_connection_string(db_type, cs)
            except Exception as e:
                _add(f"connection_string invalid: {e}")
        for k in ["host","port","login","password"]:
            v = sec.get(k)
            if v is None:
                continue
            try:
                if k == "host": validate_host(v)
                elif k == "port": validate_port(v)
                else: validate_non_empty(k, v)
            except Exception as e:
                _add(f"{k}: {e}")
    else:
        for k, v in sec.items():
            if v is None:
                continue
            try:
                if k == "connection_string": _v_cloud_connstr(v)
                elif k == "aws_access_key_id":
                    if not AWS_ACCESS_KEY_ID_RE.fullmatch(v): raise ValueError("AWS Access Key ID must be 20 uppercase letters/digits.")
                elif k == "aws_secret_access_key":
                    if not AWS_SECRET_ACCESS_KEY_RE.fullmatch(v): raise ValueError("AWS Secret must be 40 chars using A–Z, a–z, 0–9, /, +, =.")
                elif k == "region_name":
                    if not AWS_REGION_RE.fullmatch(v): raise ValueError("Region must look like 'us-east-1'.")
                elif k == "container_name":
                    if not AZURE_CONTAINER_RE.fullmatch(v): raise ValueError("Container: lowercase 3–63, hyphens ok.")
                elif k == "bucket_name":
                    if not BUCKET_RE.fullmatch(v): raise ValueError("Bucket: lowercase 3–63, dots/hyphens ok.")
                elif k == "key_json":
                    json.loads(v)
            except Exception as e:
                _add(f"{k}: {e}")

    return out

def _compute_missing_secrets_from_state(st: State, file_secrets: Dict[str, Dict[str, Optional[str]]]) -> Dict[str, List[str]]:
    missing: Dict[str, List[str]] = {}

    def need(side, keys):
        if keys:
            missing.setdefault(side, []).extend(keys)

    def db_side_missing(side: str, db_type: str) -> List[str]:
        have = (file_secrets or {}).get(side, {}) or {}
        cs = (have.get("connection_string") or "").strip()

        
        if cs:
            try:
                validate_db_connection_string(db_type, cs)
                return []
            except Exception:
                return ["connection_string"]  

        bad_or_missing: List[str] = []
        checks = (
            ("host",   validate_host),
            ("port",   validate_port),
            ("login",  lambda v: validate_non_empty("login", v)),
            ("password", lambda v: validate_non_empty("password", v)),
        )
        for k, fn in checks:
            v = have.get(k)
            if v in (None, ""):
                bad_or_missing.append(k)
                continue
            try:
                fn(v)
            except Exception:
                bad_or_missing.append(k)
        return bad_or_missing

    # SOURCE
    if st.sourceType in DB_LIKE_TYPES:
        need("source_db", db_side_missing("source_db", st.sourceType))

    # DEST
    if st.destType in DB_LIKE_TYPES:
        need("dest_db", db_side_missing("dest_db", st.destType))

   
    return {k: v for k, v in missing.items() if v}


# Field capture / consistency
def explain_invalid(field: str) -> str:
    return {
        "sourceType": "Unsupported source type.",
        "sourceJobType": "Unsupported source job type.",
        "sourceName": "Source name must be 1–64 chars [A-Za-z0-9_-]",
        "tableName": "Use 'schema.table' or 'table'",
        "sourceObjectName": "Provide object key (cloud source)",
        "sourceDatabase": "Source database must be [A-Za-z0-9_-]",
        "destType": "Unsupported destination type.",
        "destinationJobType": "Unsupported destination job type.",
        "destName": "Destination name must be 1–64 chars [A-Za-z0-9_-]",
        "destTableName": "Use 'schema.table' or 'table'",
        "sourceBucketName": "Bucket must be lowercase w/ dots or hyphens",
        "destBucketName": "Bucket must be lowercase w/ dots or hyphens",
        "destObjectName": "Provide a key (cloud destination)",
        "sourceCloudConnType": "Choose a cloud connection type",
        "destCloudConnType": "Choose a cloud connection type",
        "scheduleInterval": "Not in allowed schedules",
        "startDate": "Must be MM/DD/YYYY (or say 'today'/'tomorrow')",
        "sourceColumns": "Comma names or 'none'/'null'; blank → skip",
        "destColumns": "Comma names (same count) or 'same'/'none' tokens",
        "transformationsSpec": "Use ';' between cols, '|' within; or 'none'",
        "destDatabase": "Destination database must be [A-Za-z0-9_-]",
    }.get(field, "Invalid value")

def try_capture_field(needed: str, user_text: str) -> Tuple[Optional[str], Optional[str]]:
    t = "" if user_text is None else user_text.strip()
    t = re.sub(r'^(?:to|as)\s+', '', t, flags=re.IGNORECASE)

    if needed == "sourceType":
      v = _canonicalize_type(t)
      return ((v, None) if v in ALL_TYPES_CANON else (None, f"Choose one of: {', '.join(sorted(ALL_TYPES_CANON))}"))
    if needed == "sourceJobType":
        return (t.upper(), None) if t else (None, explain_invalid(needed))
    if needed == "sourceName":
        return ((t, None) if t and NAME_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "sourceDatabase":
        return ((t, None) if t and DB_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "tableName":
        return ((t, None) if t and TABLE_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "sourceBucketName":
        t = t.strip().lower()
        return ((t, None) if t and BUCKET_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "sourceObjectName":
        return (t, None) if (t and len(t) <= 256) else (None, explain_invalid(needed))
    if needed == "sourceCloudConnType":
        u = t.upper(); return ((u, None) if (u in CLOUD_CONN_TYPES or not CLOUD_CONN_TYPES) else (None, explain_invalid(needed)))
    if needed == "destType":
        v = _canonicalize_type(t); return ((v, None) if v in ALL_TYPES_CANON else (None, f"Choose one of: {', '.join(sorted(ALL_TYPES_CANON))}"))
    if needed == "destinationJobType":
        return (t.upper(), None) if t else (None, explain_invalid(needed))
    if needed == "destName":
        return ((t, None) if t and NAME_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "destDatabase":
        return ((t, None) if t and DB_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "destTableName":
        return ((t, None) if t and TABLE_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "destBucketName":
        t = t.strip().lower()
        return ((t, None) if t and BUCKET_RE.fullmatch(t) else (None, explain_invalid(needed)))
    if needed == "destObjectName":
        return (t, None) if (t and len(t) <= 256) else (None, explain_invalid(needed))
    if needed == "destCloudConnType":
        u = t.upper(); return ((u, None) if (u in CLOUD_CONN_TYPES or not CLOUD_CONN_TYPES) else (None, explain_invalid(needed)))

    if needed == "scheduleInterval":
        for sym in (ALLOWED_SCHEDULES_CREATING | ALLOWED_SCHEDULES_TRIGGER):
            if t.lower() == sym.lower(): return sym, None
        m = {"daily":"Daily","weekly":"Weekly","monthly":"Monthly","once":"Once","@once":"@once","@ once":"@once","@once ":"@once"}
        v = m.get(t.lower().strip())
        return (v, None) if v else (None, explain_invalid(needed))
    if needed == "startDate":
        if t == "" or t.lower() in {"today","now"}:
            return (_today_mmddyyyy(), None)
        if t.lower() == "tomorrow":
            dt = datetime.datetime.now() + datetime.timedelta(days=1); return (dt.strftime("%m/%d/%Y"), None)
        ok = re.fullmatch(r"\d{2}/\d{2}/\d{4}", t)
        if ok:
            try:
                datetime.datetime.strptime(t, "%m/%d/%Y"); return t, None
            except Exception:
                pass
        return None, explain_invalid(needed)

    if needed == "sourceColumns":
        txt = (t or "").lower()
        if txt in _MAPPING_OPTOUT_ANY:
            return "__NO_COLUMN_MAP__", None
        cols = parse_columns_list_allow_none(t)
        return ((",".join(cols), None) if cols is not None else (None, explain_invalid(needed)))
    if needed == "destColumns": return (t, None)
    if needed == "transformationsSpec": return (t, None)
    if needed == "noColumnMap":
        v = (t or "").strip().lower()
        if v in {"true","1","yes","y","on","skip","none","no columns","no column"}:
            return True, None
        if v in {"false","0","no","n","off"}:
            return False, None
        return None, "Invalid value"
    return None, "Invalid value"

def _consistency_or_error(st: State) -> Optional[str]:
    if isinstance(st.sourceColumns, str):
        if st.sourceColumns.strip().lower() in _MAPPING_OPTOUT_ANY:
            st.noColumnMap = True
            st.sourceColumns = None
            st.destColumns = None
            st.transformationsSpec = None
            return None
    if st.noColumnMap or (st.sourceColumns is None):
        st.noColumnMap=True; st.sourceColumns=None; st.destColumns=None; st.transformationsSpec=None
        return None

    sc_list = parse_columns_list_allow_none(st.sourceColumns or "")
    if sc_list is None: return "Invalid sourceColumns format."
    effective_mask = [(s and s.lower() not in {"none","null"}) for s in sc_list]
    if not any(effective_mask):
        st.noColumnMap=True; st.sourceColumns=None; st.destColumns=None; st.transformationsSpec=None
        return None

    n_total = len(sc_list)
    if st.destColumns is None:
        dest_list = ["same"] * n_total
    else:
        dest_list = parse_dest_columns_allow_tokens(st.destColumns, n_total)
        if dest_list is None: return "Destination columns must match source count."

    t_parsed = parse_transformations_spec(st.transformationsSpec or "", n_total)
    if t_parsed is None:
        return "Transformations must be 'none'/blank or match source count with ';' and '|' tokens."

    eff_sc, eff_dc, eff_ts = [], [], []
    for i in range(n_total):
        if not effective_mask[i]: continue
        sname = sc_list[i]; dtoken = dest_list[i]; steps_list = t_parsed[i]
        if dtoken == "" or (isinstance(dtoken, str) and dtoken.lower() in {"none","null"}):
            dname, steps = "", []
        elif isinstance(dtoken, str) and dtoken.lower() == "same":
            dname, steps = sname, steps_list
        else:
            dname, steps = dtoken, steps_list
        eff_sc.append(sname); eff_dc.append(dname); eff_ts.append("|".join(steps))

    st.sourceColumns = ",".join(eff_sc)
    st.destColumns = ",".join(eff_dc)
    st.transformationsSpec = ";".join(eff_ts)
    return None

# JSON builders & validators
def _uuid() -> str: return str(uuid.uuid4())
def _today_mmddyyyy() -> str: return datetime.datetime.now().strftime("%m/%d/%Y")

def avro_validate_or_raise(schema_key: str, data: dict):
    schema = SCHEMAS[schema_key]
    if _AVRO_HAS_VALIDATE and avro_validate(schema, data):
        return data
    try:
        buf = io.BytesIO()
        from avro.io import BinaryEncoder, DatumWriter  # type: ignore
        enc = BinaryEncoder(buf); writer = DatumWriter(schema); writer.write(data, enc)
        return data
    except AvroTypeException as e:
        raise ValueError(f"{schema_key} failed Avro validation: {e}") from e
    except Exception as e:
        raise ValueError(f"{schema_key} failed Avro validation: {e}") from e

def custom_validation_rules(schema_key: str, data: dict):
    if data is None: return
    problems = []
    def add(fn, *args, **kwargs):
        try: fn(*args, **kwargs)
        except Exception as e: problems.append(str(e))
    if schema_key == "creating":
        validate_enum("scheduleInterval", data.get("scheduleInterval"), ALLOWED_SCHEDULES_CREATING)
        jobs = data.get("jobs")
        if not isinstance(jobs, list) or not jobs:
            problems.append("jobs must be a non-empty array")
        else:
            for idx, job in enumerate(jobs):
                src = (job or {}).get("source", {}) or {}
                sp = src.get("sourceProperties", {}) or {}
                stype = src.get("sourceType")
                validate_enum(f"jobs[{idx}].source.sourceType", stype, ALL_TYPES_CANON)
                add(validate_non_empty, f"jobs[{idx}].source.sourceName", src.get("sourceName"))
                add(validate_non_empty, f"jobs[{idx}].source.sourceProperties.taskId", sp.get("taskId"))
                add(validate_non_empty, f"jobs[{idx}].source.sourceProperties.connectionId", sp.get("connectionId"))
                dests = job.get("destinations")
                if not isinstance(dests, list) or not dests:
                    problems.append(f"jobs[{idx}].destinations must be a non-empty array")
                else:
                    for jdx, d in enumerate(dests):
                        d = d or {}
                        dtype = d.get("destinationType")
                        add(validate_non_empty, f"jobs[{idx}].destinations[{jdx}].destinationName", d.get("destinationName"))
                        validate_enum(f"jobs[{idx}].destinations[{jdx}].destinationType", dtype, ALL_TYPES_CANON)
                        dp = d.get("destinationProperties", {}) or {}
                        add(validate_non_empty, f"jobs[{idx}].destinations[{jdx}].destinationProperties.taskId", dp.get("taskId"))
                        add(validate_non_empty, f"jobs[{idx}].destinations[{jdx}].destinationProperties.connectionId", dp.get("connectionId"))
    elif schema_key == "dbconn":
        for fld in ["conn_id","conn_type","host","port","login","password"]:
            add(validate_non_empty, f"dbconn.{fld}", str(data.get(fld) or ""))
        add(validate_host, data.get("host"))
        add(validate_port, data.get("port"))
    elif schema_key == "cloudconn":
        for fld in ["conn_id","conn_type"]:
            add(validate_non_empty, f"cloudconn.{fld}", str(data.get(fld) or ""))
        for opt in ["connection_string","aws_access_key_id","aws_secret_access_key","region_name",
                    "container_name","bucket_name","key_json","login","password","securityToken"]:
            v = data.get(opt)
            if v is not None and not isinstance(v, str):
                problems.append(f"cloudconn.{opt} must be a string or null")
        try:
            _v_cloud_connstr(data.get("connection_string"))
        except Exception as e:
            problems.append(str(e))

        # bucket (if present)
        try:
            _v_bucket(data.get("bucket_name"))
        except Exception as e:
            problems.append(str(e))

        # container (if present)
        if data.get("container_name"):
            if not AZURE_CONTAINER_RE.fullmatch(data["container_name"]):
                problems.append("Container: lowercase 3–63, hyphens ok.")

        # region (if present)
        if data.get("region_name") and not AWS_REGION_RE.fullmatch(data["region_name"]):
            problems.append("Region must look like 'us-east-1'.")

        # key_json MUST be valid JSON if present
        kj = data.get("key_json")
        if kj not in (None, ""):
            try:
                json.loads(kj)
            except Exception:
                problems.append("key_json must be valid JSON text.")

    elif schema_key == "trigger":
        validate_enum("scheduleInterval", data.get("scheduleInterval"), ALLOWED_SCHEDULES_TRIGGER)
        for fld in ["pipelineId","runId"]:
            add(validate_non_empty, fld, data.get(fld))
    elif schema_key == "delete_conn":
        add(validate_non_empty, "conn_id", data.get("conn_id"))
    if problems: raise ValueError("Validation failed: " + "; ".join(problems))

def _v_cloud_connstr(v: Optional[str]):
    if v in (None, ""): return
    ok_prefixes = ("s3://","gs://","abfss://","wasbs://","azure://","gcs://")
    if not any((v.lower()).startswith(p) for p in ok_prefixes):
        if "://" in v:
            raise ValueError("Unsupported cloud connection string scheme. Expected one of: s3://, gs://, abfss://, wasbs://.")

# Secrets & payload finishing
def fill_ids_and_secrets(doc: dict, st: State, secrets_by_side: dict):
    _consistency_or_error(st)
    creating_in = (doc or {}).get("creating") or {}
    trigger_in  = (doc or {}).get("trigger")  or {}
    delete_dag_in = (doc or {}).get("delete_dag") or {}
    delete_conn_in= (doc or {}).get("delete_conn") or {}

    pipeline_id = creating_in.get("pipelineId") or _uuid()
    run_id      = trigger_in.get("runId") or _uuid()
    src_task = _uuid(); dst_task = _uuid(); job_id = _uuid()
    src_conn_id = (
        creating_in.get("jobs", [{}])[0].get("source", {}).get("sourceProperties", {}).get("connectionId")
    ) or _uuid()
    dest_conn_id = (
        creating_in.get("jobs", [{}])[0].get("destinations", [{}])[0].get("destinationProperties", {}).get("connectionId")
    ) or _uuid()

    source_props = {
        "taskId": src_task, "connectionId": src_conn_id,
        "tableName": (st.tableName if st.sourceType in DB_TYPES_CANON else None),
        "bucketName": (st.sourceBucketName if st.sourceType in CLOUD_DB_TYPES else None),
        "containerName": None, "schemaName": None,
        "objectName": (st.sourceObjectName if st.sourceType in CLOUD_DB_TYPES else None),
        "sourceJobType": st.sourceJobType, "customQuery": None,
    }
    dest_props = {
        "taskId": dst_task, "connectionId": dest_conn_id,
        "tableName": (st.destTableName if st.destType in DB_TYPES_CANON else None),
        "bucketName": (st.destBucketName if st.destType in CLOUD_DB_TYPES else None),
        "containerName": None, "schemaName": None,
        "objectName": (st.destObjectName if st.destType in CLOUD_DB_TYPES else None),
        "sourceJobType": st.destinationJobType, "customQuery": None,
    }

    join_md=[]
    if not st.noColumnMap and (st.sourceColumns or "") != "":
        if st.destColumns in (None, ""):
            st.destColumns = st.sourceColumns

        sc=(st.sourceColumns or "").split(",")
        dc=(st.destColumns or "").split(",")
        ts=((st.transformationsSpec or "").split(";") if (st.transformationsSpec or "")!="" else [""]*len(sc))
        for i,sname in enumerate(sc):
            dname = dc[i] if i < len(dc) else ""
            steps = ([] if (i>=len(ts) or ts[i]=="" or ts[i].lower() in {"none","null"})
                     else [t for t in ts[i].split("|") if t.strip()])
            jm_id=_uuid(); src_md=_uuid(); dst_md=_uuid(); grp_id=_uuid()
            join_md.append({
                "joinMetadataTaskId": jm_id, "sourceMetadataId": src_md, "destinationMetadataId": dst_md,
                "sourceColumnName": sname, "destinationColumnName": dname,
                "sourceGroupId": grp_id, "destinationTaskId": dest_props["taskId"], "sourceTaskId": source_props["taskId"],
                "transformations": {"ids": steps, "parent": dst_md},
            })

    creating = {
        "pipelineId": pipeline_id,
        "scheduleInterval": (st.scheduleInterval if st.scheduleInterval != "@once" else "Once"),
        "startDate": st.startDate or _today_mmddyyyy(), "catchup": False,
        "jobs": [{
            "id": job_id,
            "source": {"sourceName": st.sourceName, "sourceType": st.sourceType, "sourceProperties": source_props},
            "destinations": [{
                "destinationName": st.destName, "destinationType": st.destType, "destinationProperties": dest_props
            }],
            "joinMetadata": join_md,
        }],
        "sequence": {job_id: []}, "taskSequence": {source_props["taskId"]: [dest_props["taskId"]]},
    }
    trigger = {"pipelineId": pipeline_id, "runId": run_id,
               "scheduleInterval": (st.scheduleInterval if st.scheduleInterval in ALLOWED_SCHEDULES_TRIGGER else "Once"),
               "startDate": st.startDate or _today_mmddyyyy(), "catchup": False}

    delete_conn = _prune_to_schema_fields("delete_conn", delete_conn_in or {"conn_id": src_conn_id})
    delete_dag  = _prune_to_schema_fields("delete_dag",  delete_dag_in  or {"pipelineId": pipeline_id, "runId": run_id})

    db_source = cloud_source = db_dest = cloud_dest = None

    if st.sourceType in DB_TYPES_CANON:
        sec = secrets_by_side.get("source_db", {}) or {}
        cs = sec.get("connection_string")
        if cs:
            parts = validate_db_connection_string(st.sourceType, cs)
            sec = {
                "host": sec.get("host") or parts.get("host"),
                "port": sec.get("port") or parts.get("port"),
                "login": sec.get("login") or parts.get("login"),
                "password": sec.get("password") or parts.get("password"),
            }
            if st.sourceType in {"MYSQL","PSQL"} and not st.sourceDatabase and parts.get("database"): st.sourceDatabase=parts["database"]
            if st.sourceType=="MSSQL" and not st.sourceDatabase and parts.get("database"): st.sourceDatabase=parts["database"]
            if st.sourceType=="ORACLE" and not st.sourceDatabase and parts.get("service_name"): st.sourceDatabase=parts["service_name"]
        db_source = _prune_to_schema_fields("dbconn", {
            "conn_id": src_conn_id, "conn_type": st.sourceType,
            "host": sec.get("host"), "port": sec.get("port") or str(DEFAULT_PORTS.get(st.sourceType, "")),
            "login": sec.get("login"), "password": sec.get("password"),
            "database": st.sourceDatabase,
        })
    elif st.sourceType in CLOUD_DB_TYPES:
        sec = secrets_by_side.get("source_cloud", {}) or {}
        cloud_source = {"conn_id": src_conn_id, "conn_type": st.sourceCloudConnType}; _ensure_cloud_keys(cloud_source)
        for k,v in sec.items():
            if v is not None: cloud_source[k]=v
        if not cloud_source.get("bucket_name"): cloud_source["bucket_name"]=st.sourceBucketName
        cloud_source = _prune_to_schema_fields("cloudconn", cloud_source)

    if st.destType in DB_TYPES_CANON:
        sec = secrets_by_side.get("dest_db", {}) or {}
        cs = sec.get("connection_string")
        if cs:
            parts = validate_db_connection_string(st.destType, cs)
            sec = {
                "host": sec.get("host") or parts.get("host"),
                "port": sec.get("port") or parts.get("port"),
                "login": sec.get("login") or parts.get("login"),
                "password": sec.get("password") or parts.get("password"),
            }
            if st.destType in {"MYSQL","PSQL"} and not st.destDatabase and parts.get("database"): st.destDatabase=parts["database"]
            if st.destType=="MSSQL" and not st.destDatabase and parts.get("database"): st.destDatabase=parts["database"]
            if st.destType=="ORACLE" and not st.destDatabase and parts.get("service_name"): st.destDatabase=parts["service_name"]
        db_dest = _prune_to_schema_fields("dbconn", {
            "conn_id": dest_conn_id, "conn_type": st.destType,
            "host": sec.get("host"), "port": sec.get("port") or str(DEFAULT_PORTS.get(st.destType, "")),
            "login": sec.get("login"), "password": sec.get("password"),
            "database": st.destDatabase,
        })
    elif st.destType in CLOUD_DB_TYPES:
        sec = secrets_by_side.get("dest_cloud", {}) or {}
        cloud_dest = {"conn_id": dest_conn_id, "conn_type": st.destCloudConnType}; _ensure_cloud_keys(cloud_dest)
        for k,v in sec.items():
            if v is not None: cloud_dest[k]=v
        if not cloud_dest.get("bucket_name"): cloud_dest["bucket_name"]=st.destBucketName
        cloud_dest = _prune_to_schema_fields("cloudconn", cloud_dest)

    return creating, trigger, delete_dag, delete_conn, (db_source, cloud_source), (db_dest, cloud_dest)

# NLP: freeform parsing
FRIENDLY_TO_CANON = {
    # source
    "source type": "sourceType",
    "source db type": "sourceType",
    "source job type": "sourceJobType",
    "source name": "sourceName",
    "source db": "sourceDatabase",
    "src db": "sourceDatabase",
    "source database": "sourceDatabase",
    "source data base": "sourceDatabase",
    "source db name": "sourceDatabase",
    "source database name": "sourceDatabase",
    "source tablename": "tableName",
    "source table name": "tableName",
    "table name": "tableName",
    "source bucket name": "sourceBucketName",
    "source object name": "sourceObjectName",
    "source cloud conn type": "sourceCloudConnType",
    "source cloud type": "sourceCloudConnType",
    "source cloud connection type": "sourceCloudConnType",
    "source columns": "sourceColumns",
    # dest
    "dest type": "destType",
    "destination type": "destType",
    "dest name": "destName",
    "dest source name": "destName",
    "destination name": "destName",
    "destination source name": "destName",
    "dest job type": "destinationJobType",
    "destination job type": "destinationJobType",
    "destination db name": "destDatabase",
    "dest db": "destDatabase",
    "dest db name": "destDatabase",
    "destination db": "destDatabase",
    "destination db name": "destDatabase",
    "dest database": "destDatabase",
    "dest data base": "destDatabase",
    "destination database": "destDatabase",
    "destination data base": "destDatabase",
    "destination database name": "destDatabase",
    "dest table name": "destTableName",
    "destination table name": "destTableName",
    "dest bucket name": "destBucketName",
    "destination bucket name": "destBucketName",
    "dest object name": "destObjectName",
    "destination object name": "destObjectName",
    "dest cloud conn type": "destCloudConnType",
    "destination cloud conn type": "destCloudConnType",
    "dest cloud connection type": "destCloudConnType",
    "destination cloud connection type": "destCloudConnType",
    "dest columns": "destColumns",
    "destination columns": "destColumns",
    # schedule/date/transform
    "schedule": "scheduleInterval",
    "interval": "scheduleInterval",
    "schedule interval": "scheduleInterval",
    "scheduleinterval": "scheduleInterval",
    "start date": "startDate",
    "transformations spec": "transformationsSpec",
    "transformations": "transformationsSpec",
    "transform spec": "transformationsSpec",
    "transformation spec": "transformationsSpec",
}
KEY_ALIASES = {
    # src
    "sourcetype":"sourceType", "sourcedbtype":"sourceType", "srcdbtype":"sourceType",
    "sourcejobtype":"sourceJobType", "sourcejob":"sourceJobType","source job type":"sourceJobType", "source jobtype":"sourceJobType","source job":"sourceJobType",
    "sourcename":"sourceName", "source name":"sourceName","sourcedatabase":"sourceDatabase","sourcedbname": "sourceDatabase", "sourcedb":"sourceDatabase","source database":"sourceDatabase","source data base":"sourceDatabase", "source db":"sourceDatabase","sourcedatabasename": "sourceDatabase",
    "tablename":"tableName", "table name":"tableName","sourcebucketname":"sourceBucketName", "sourceobjectname":"sourceObjectName","source bucketname":"sourceBucketName", "source objectname":"sourceObjectName","source bucket name":"sourceBucketName", "source object name":"sourceObjectName",
    "sourcecloudconntype":"sourceCloudConnType", "sourcecolumns":"sourceColumns","source cloudconntype":"sourceCloudConnType", "source columns":"sourceColumns","source cloud conntype":"sourceCloudConnType", "source cloud conn type":"sourceCloudConnType","source column":"sourceColumns","sourcecloudconnectiontype": "sourceCloudConnType",

    # dest
    "desttype":"destType","destinationtype":"destType","dest type":"destType","destination type":"destType","destinationsourcename": "destName","destname":"destName","destinationname":"destName","dest name":"destName","destination name":"destName","destsourcename": "destName",
    "destdatabase":"destDatabase","destinationdbname": "destDatabase","destinationdatabase":"destDatabase","dest database":"destDatabase","destination database":"destDatabase","dest data base":"destDatabase","destination data base":"destDatabase","dest db":"destDatabase","destination db":"destDatabase","destinationdatabasename": "destDatabase",
    "desttablename":"destTableName","desttable":"destTableName","destinationtable":"destTableName","dest tablename":"destTableName","dest table":"destTableName","destination table":"destTableName","dest table name":"destTableName",
    "destbucketname":"destBucketName","dest bucketname":"destBucketName","dest bucket name":"destBucketName","destobjectname":"destObjectName","dest objectname":"destObjectName","dest object name":"destObjectName","destcloudconntype":"destCloudConnType","dest cloudconntype":"destCloudConnType","dest cloud conntype":"destCloudConnType","dest cloud conn type":"destCloudConnType","destcloudconnectiontype": "destCloudConnType","destinationcloudconnectiontype": "destCloudConnType",
    "destcolumns":"destColumns","destinationcolumns":"destColumns","destination columns":"destColumns","destination column":"destColumns","destcolumn":"destColumns","destinationcolumn":"destColumns",
    "destinationjobtype": "destinationJobType","destjobtype": "destinationJobType","destination jobtype": "destinationJobType","dest jobtype": "destinationJobType","destination job type": "destinationJobType","dest job type": "destinationJobType",
    # sched/date/tx
    "schedule":"scheduleInterval","scheduled": "scheduleInterval","interval":"scheduleInterval","scheduleinterval": "scheduleInterval", "schedule interval": "scheduleInterval","schedule_interval":"scheduleInterval","startdate":"startDate","start date":"startDate",
    "transformationsspec":"transformationsSpec","transformations":"transformationsSpec","transformspec":"transformationsSpec","transformations spec":"transformationsSpec","transform spec":"transformationsSpec","transformationspec": "transformationsSpec","transformation spec": "transformationsSpec","transformation_spec": "transformationsSpec",
}
_KEYPOOL = set(list(FRIENDLY_TO_CANON.keys()) + list(KEY_ALIASES.keys()))
KEY_ALT = "|".join(sorted([re.escape(k) for k in _KEYPOOL], key=len, reverse=True))

SEP = r"(?:=|:|->|=>|\bis\b|\bare\b)?"

VALUE_STOP = r"(?=(?:\s+(?:no\s+)?(?:" + KEY_ALT + r")\s*" + SEP + r")|(?:\s+and\s+)|$)"

PAIR_RE = re.compile(
    r"(?P<key>" + KEY_ALT + r")\s*" + SEP + r"\s*(?P<val>.*?)" + VALUE_STOP,
    re.IGNORECASE | re.DOTALL,
)

_TYPES_TOKENS = sorted(set([
    "mysql", "my sql",
    "psql", "postgres", "postgresql", "pg",
    "sql server", "mssql", "mssqlserver", "ms sql", "ms sql server",
    "oracle", "ora",
    "aws rds", "amazon rds", "rds",
    "amazon aurora", "aurora",
    "gcp cloud sql", "cloud sql", "google cloud sql",
]))
_TYPES_ALT = r"(?:%s)" % "|".join(re.escape(t) for t in _TYPES_TOKENS)
FROM_TO_RE = re.compile(
    rf"\bfrom\s+(?P<src>{_TYPES_ALT})\s+to\s+(?P<dst>{_TYPES_ALT})\b",
    re.IGNORECASE
)
NO_COLUMNS_HINT_RE = re.compile(r"\bno\s+(?:source\s+)?columns?\b", re.IGNORECASE)


def parse_freeform(blob: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    text = (blob or "").strip()
    low = text.lower()
    if (
        re.search(r"\bno\s+source\s+columns?\b", low)
        or re.search(r"\bno\s+columns?\b", low)
        or re.search(r"\bno\s+column\s+mapping\b", low)
        or re.search(r"\bskip\s+column\s+mapping\b", low)
    ):
        out["sourceColumns"] = "no"

    for tok, norm in [("daily","Daily"),("weekly","Weekly"),("monthly","Monthly"),("once","Once"),("@once","@once")]:
        if re.search(r"\b" + re.escape(tok) + r"\b", low):
            out["scheduleInterval"] = norm
            break

    m = FROM_TO_RE.search(low)
    if m:
        src_t, dst_t = m.group("src").strip(), m.group("dst").strip()
        out["sourceType"] = _canonicalize_type(src_t) or src_t
        out["destType"]   = _canonicalize_type(dst_t) or dst_t


    for mm in PAIR_RE.finditer(text):
        k = mm.group("key").strip().lower()
        v = mm.group("val").strip().strip(",;")
        canon = FRIENDLY_TO_CANON.get(k)
        if not canon:
            canon = KEY_ALIASES.get(_norm_token_strict(k))
        if not canon:
            continue
        if canon in {"sourceType","destType"}:
            v = _canonicalize_type(v) or v
        elif canon == "scheduleInterval":
            vv = v.lower()
            v = {"daily":"Daily","weekly":"Weekly","monthly":"Monthly","once":"Once","@once":"@once"}.get(vv, v)
        elif canon == "startDate":
            vv = v.lower()
            if vv in {"today","now"}: v = _today_mmddyyyy()
            elif vv == "tomorrow": v = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%m/%d/%Y")
        out[canon] = v

    for token in re.split(r"(?:,|;|\n|\s+and\s+)", text):
        token = token.strip()
        if not token: continue
        if "=" in token or ":" in token:
            kv = re.split(r"\s*(?:=|:)\s*", token, maxsplit=1)
            if len(kv) == 2:
                k_raw, v_raw = kv[0].strip(), kv[1].strip()
                canon = KEY_ALIASES.get(_norm_token_strict(k_raw))
                if canon:
                    if canon in {"sourceType","destType"}:
                        v_raw = _canonicalize_type(v_raw) or v_raw
                    elif canon == "scheduleInterval":
                        v_raw = {"daily":"Daily","weekly":"Weekly","monthly":"Monthly","once":"Once","@once":"@once"}.get(v_raw.lower(), v_raw)
                    elif canon == "startDate":
                        if v_raw.lower() in {"today","now"}: v_raw = _today_mmddyyyy()
                        elif v_raw.lower() == "tomorrow": v_raw = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%m/%d/%Y")
                    out[canon] = v_raw
    m_sc = re.search(r'\bsource\s*columns?\s*(?:is|=|:)\s*([A-Za-z0-9_,\s]+)', text, re.IGNORECASE)
    m_dc = re.search(r'\bdest(?:ination)?\s*columns?\s*(?:is|=|:)\s*([A-Za-z0-9_,\s]+)', text, re.IGNORECASE)
    m_tx = re.search(r'\btransformation(?:s)?\s*spec(?:ification)?\s*(?:is|=|:)\s*([A-Za-z0-9_\s|,]+)', text, re.IGNORECASE)

    if m_sc and "sourceColumns" not in out:
        out["sourceColumns"] = re.sub(r'\s+', '', m_sc.group(1))
    if m_dc and "destColumns" not in out:
        out["destColumns"]   = re.sub(r'\s+', '', m_dc.group(1))
    if m_tx and "transformationsSpec" not in out:
        raw = m_tx.group(1).strip()
        if "|" not in raw and re.search(r"\bto\b", raw, re.IGNORECASE):
            raw = re.sub(r"\s*\bto\b\s*", "|", raw, flags=re.IGNORECASE)
        out["transformationsSpec"] = raw

    return out

# LLM driver
SYSTEM_PROMPT = """You are an expert data-migration assistant.

Goal:
- Parse the user's free text for any supported fields.
- Then respond with STRICT JSON:
  {
    "action": "ask" | "finalize",
    "missing_keys": [...],          // required fields not yet provided
    "question": "<one short sentence asking for ONLY the missing keys in a single batch>",
    "fields": { "<field>": "<value>", ... } // echo back any parsed fields from this turn (optional)
  }

Rules:
- NEVER ask for secrets (passwords, keys, tokens, hosts, ports). Those are collected locally.
- Column mapping:
  * sourceColumns is OPTIONAL. If user leaves it empty/none/skip, we SKIP column mapping entirely (no destColumns or transformationsSpec).
  * If sourceColumns ARE provided: destColumns MAY be omitted (assume 'same' when missing), and transformationsSpec is STILL OPTIONAL.
- Schedules: Daily, Weekly, Monthly, Once, @once.
- Dates: MM/DD/YYYY or 'today'/'tomorrow'.
- Be concise; single question string when action='ask'.
"""

def _required_fields(st: State) -> List[str]:
    req: List[str] = ["sourceType","sourceJobType","sourceName"]
    if st.sourceType in CLOUD_DB_TYPES:
        req += ["sourceBucketName","sourceObjectName","sourceCloudConnType"]
    elif st.sourceType:
        req += ["sourceDatabase","tableName"]
    req += ["destType","destinationJobType","destName"]
    if st.destType in CLOUD_DB_TYPES:
        req += ["destBucketName","destObjectName","destCloudConnType"]
    elif st.destType:
        req += ["destDatabase","destTableName"]
    req += ["scheduleInterval","startDate"]
    return req

def _normalize_type_dependencies(st: State):
    if st.sourceType in DB_TYPES_CANON:
        st.sourceBucketName = None
        st.sourceObjectName = None
        st.sourceCloudConnType = None
    elif st.sourceType in CLOUD_DB_TYPES:
        st.sourceDatabase = None
        st.tableName = None

    if st.destType in DB_TYPES_CANON:
        st.destBucketName = None
        st.destObjectName = None
        st.destCloudConnType = None
    elif st.destType in CLOUD_DB_TYPES:
        st.destDatabase = None
        st.destTableName = None

def _quick_bind_single_value(st: State, text: str) -> List[str]:

    txt = (text or "").strip()
    if not txt:
        return []
    if parse_freeform(txt):
        return []

    errs: List[str] = []
    missing = set(_compute_missing(st))

    def _apply(key: str, val: str):
        new_val, err = try_capture_field(key, val)
        if new_val is None:
            errs.append(f"{key}: {err or 'Invalid'}")
            return
        if key == "sourceColumns" and new_val == "__NO_COLUMN_MAP__":
            st.noColumnMap = True
            st.sourceColumns = None
            st.destColumns = None
            st.transformationsSpec = None
        else:
            setattr(st, key, new_val if new_val != "" else None)

    if re.fullmatch(r'(?:no\s+source\s+columns?|no\s+columns?|no\s+mapping|skip|none|n/?a|na)$', txt, flags=re.IGNORECASE):
        st.noColumnMap = True
        st.sourceColumns = None
        st.destColumns = None
        st.transformationsSpec = None
        return []

    m = re.search(r'\bdest(?:ination)?\s*(?:db|database|db\s*name)\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,128})\b', txt, re.IGNORECASE)
    if m and "destDatabase" in missing:
        _apply("destDatabase", m.group(1))

    m = re.search(r'\bsource\s*(?:db|database|db\s*name)\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,128})\b', txt, re.IGNORECASE)
    if m and "sourceDatabase" in missing:
        _apply("sourceDatabase", m.group(1))

    if ("destDatabase" in missing) or ("sourceDatabase" in missing):
        m_head = re.search(r'\b(?:db\s*name|database)\b', txt, re.IGNORECASE)
        if m_head:
            m_val = re.search(r'\b(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,128})\b', txt[m_head.end():], re.IGNORECASE)
            if m_val:
                if "destDatabase" in missing:
                    _apply("destDatabase", m_val.group(1))
                elif "sourceDatabase" in missing:
                    _apply("sourceDatabase", m_val.group(1))

    m = re.search(r'\b(?:schedule|interval)\s*(?:is|=|:)?\s*([@]?\w+)\b', txt, re.IGNORECASE)
    if m and "scheduleInterval" in missing:
        _apply("scheduleInterval", m.group(1))

    m = re.search(r'\bstart\s*date\s*(?:is|=|:)?\s*([0-9/]{8,10}|today|tomorrow|now)\b', txt, re.IGNORECASE)
    if m and "startDate" in missing:
        _apply("startDate", m.group(1))

    m = re.search(r'\bsource\s*cloud\s*(?:connection\s*)?type\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,64})\b', txt, re.IGNORECASE)
    if m and "sourceCloudConnType" in missing:
        _apply("sourceCloudConnType", m.group(1))
    m = re.search(r'\bdest(?:ination)?\s*cloud\s*(?:connection\s*)?type\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,64})\b', txt, re.IGNORECASE)
    if m and "destCloudConnType" in missing:
        _apply("destCloudConnType", m.group(1))

    m = re.search(r'\bdest(?:ination)?\s*name\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,64})\b', txt, re.IGNORECASE)
    if m and "destName" in missing:
        _apply("destName", m.group(1))
    m = re.search(r'\bsource\s*name\s*(?:is|=|:)?\s*([A-Za-z0-9_\-]{1,64})\b', txt, re.IGNORECASE)
    if m and "sourceName" in missing:
        _apply("sourceName", m.group(1))

    m = re.search(r'\bdest(?:ination)?\s*table\s*name\s*(?:is|=|:)?\s*([A-Za-z0-9_.]{1,128})\b', txt, re.IGNORECASE)
    if m and "destTableName" in missing:
        _apply("destTableName", m.group(1))
    m = re.search(r'\b(?:source\s*)?table\s*name\s*(?:is|=|:)?\s*([A-Za-z0-9_.]{1,128})\b', txt, re.IGNORECASE)
    if m and "tableName" in missing:
        _apply("tableName", m.group(1))

    if errs or set(_compute_missing(st)) != missing:
        return errs

    if " " not in txt:
        token = txt
        if token.lower() in {"none", "skip", "no", "n/a", "na"}:
            st.noColumnMap = True
            st.sourceColumns = None
            st.destColumns = None
            st.transformationsSpec = None
            return []
        for key in ["destDatabase", "sourceDatabase",
                    "destTableName", "tableName",
                    "destName", "sourceName",
                    "scheduleInterval", "startDate"]:
            if key in missing:
                _apply(key, token)
                break

    return errs


def _compute_missing(st: State) -> List[str]:
    return [f for f in _required_fields(st) if getattr(st, f) in (None, "")]

def _state_view(st: State) -> Dict[str, Any]:
    known = {k:getattr(st,k) for k in st.__dict__.keys() if getattr(st,k) not in (None, "")}
    return {"known": known, "required": _required_fields(st), "missing": _compute_missing(st)}

def _src_fp(d: dict):
    return (d.get("sourceType"), d.get("sourceName"), d.get("sourceDatabase"), d.get("tableName"),
            d.get("sourceBucketName"), d.get("sourceObjectName"), d.get("sourceCloudConnType"))

def _dst_fp(d: dict):
    return (d.get("destType"), d.get("destName"), d.get("destDatabase"), d.get("destTableName"),
            d.get("destBucketName"), d.get("destObjectName"), d.get("destCloudConnType"))

def _apply_fields(st: State, fields: Dict[str, Any]) -> List[str]:
    errs = []
    if not fields:
        return errs

    prev_src_type = st.sourceType
    prev_dst_type = st.destType

    for k, v in (fields or {}).items():
        if not hasattr(st, k):
            continue
        new_val, err = try_capture_field(k, str(v))
        if k == "sourceColumns":
            if new_val == "__NO_COLUMN_MAP__":
                st.noColumnMap = True
                st.sourceColumns = st.destColumns = st.transformationsSpec = None
                continue
            else:
                if new_val not in (None, ""):
                    st.noColumnMap = False

        setattr(st, k, new_val if new_val != "" else None)

    if st.sourceType != prev_src_type or st.destType != prev_dst_type:
        _normalize_type_dependencies(st)

    changed_keys = set((fields or {}).keys())
    should_normalize = ("sourceColumns" in changed_keys) or (st.sourceColumns not in (None, ""))

    if should_normalize:
        fix = _consistency_or_error(st)
        if fix:
            errs.append(f"columns: {fix}")

    return errs

def _fill_secrets_from_conn_strings_in_place(st: State, file_secrets: dict):
    for side, dbt in (("source_db", st.sourceType), ("dest_db", st.destType)):
        sec = (file_secrets or {}).get(side)
        if not (sec and isinstance(sec, dict)):
            continue
        cs = (sec.get("connection_string") or "").strip()
        if not cs:
            continue
        try:
            parts = validate_db_connection_string(dbt, cs)
            for k in ("host", "port", "login", "password"):
                if not (sec.get(k) or ""):
                    sec[k] = parts.get(k)
            if side == "source_db":
                if st.sourceType in {"MYSQL","PSQL","MSSQL"} and (not st.sourceDatabase) and parts.get("database"):
                    st.sourceDatabase = parts["database"]
                if st.sourceType == "ORACLE" and (not st.sourceDatabase) and parts.get("service_name"):
                    st.sourceDatabase = parts["service_name"]
            else:
                if st.destType in {"MYSQL","PSQL","MSSQL"} and (not st.destDatabase) and parts.get("database"):
                    st.destDatabase = parts["database"]
                if st.destType == "ORACLE" and (not st.destDatabase) and parts.get("service_name"):
                    st.destDatabase = parts["service_name"]
        except Exception:
            pass

def _llm_step(st: State, user_text: str) -> Dict[str, Any]:

    errors: List[str] = []
    _fp_src_before = _src_fp(st.to_public_dict())
    _fp_dst_before = _dst_fp(st.to_public_dict())
    _src_changed = False
    _dst_changed = False
    extracted = parse_freeform(user_text)

    safe_turn, had_secretish = _redact_for_llm(user_text)

    if not extracted:
        if had_secretish and (STRICT_NO_LLM_ON_SECRETS or not _have_llm()):
            missing = _compute_missing(st)
            return {"action": ("finalize" if not missing else "ask"),
                    "missing_keys": missing,
                    "question": _llm_missing_prompt(missing, st),
                    "errors": errors,
                    "__src_changed": _src_changed,
                    "__dst_changed": _dst_changed}
        missing, composed = _nudge_and_prompt(safe_turn, st)
        return {"action": "ask", "missing_keys": missing, "question": composed, "errors": errors}

    before = st.to_public_dict().copy()
    errors += _apply_fields(st, extracted)
    after = st.to_public_dict()
    applied_any = any(before.get(k) != after.get(k) for k in before)

    _src_changed = _src_changed or (_src_fp(before) != _src_fp(after))
    _dst_changed = _dst_changed or (_dst_fp(before) != _dst_fp(after))
    if not applied_any:
        if had_secretish and (STRICT_NO_LLM_ON_SECRETS or not _have_llm()):
            missing = _compute_missing(st)
            return {"action": ("finalize" if not missing else "ask"),
                    "missing_keys": missing,
                    "question": _llm_missing_prompt(missing, st),
                    "errors": errors}
        missing, composed = _nudge_and_prompt(safe_turn, st)
        return {"action": "ask", "missing_keys": missing, "question": composed, "errors": errors,"__src_changed": _src_changed,"__dst_changed": _dst_changed}

    if not _have_llm() or (had_secretish and STRICT_NO_LLM_ON_SECRETS):
        missing = _compute_missing(st)
        return {"action": ("finalize" if not missing else "ask"),
                "missing_keys": missing,
                "question": _llm_missing_prompt(missing, st),
                "errors": errors,
                "__src_changed": _src_changed,
                "__dst_changed": _dst_changed}

    payload = {"state": _state_for_llm(st), "user_turn": safe_turn}


    #payload = {"state": _state_view(st), "user_turn": (user_text or "").strip()}
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload)},
    ]
    try:
        last_llm_payload_contains_secret = False
        _assert_no_secrets_payload()
        resp = client.chat.completions.create(model=OPENAI_MODEL, temperature=0.2, messages=messages)
        raw = resp.choices[0].message.content
        out = json.loads(raw)
    except Exception:
        last_llm_payload_contains_secret = False
        _assert_no_secrets_payload()
        resp = client.chat.completions.create(
            model=OPENAI_MODEL, temperature=0,
            messages=messages + [{"role": "user", "content": "Return STRICT JSON only."}],
        )
        out = json.loads(resp.choices[0].message.content)

    if out.get("fields"):
        _before2 = st.to_public_dict().copy()
        errors += _apply_fields(st, out["fields"])
        _after2 = st.to_public_dict()
        _src_changed = _src_changed or (_src_fp(_before2) != _src_fp(_after2))
        _dst_changed = _dst_changed or (_dst_fp(_before2) != _dst_fp(_after2))

    missing = _compute_missing(st)
    if not missing:
        return {"action": "finalize", "missing_keys": [], "errors": errors,"__src_changed": _src_changed,"__dst_changed": _dst_changed}
    question = _llm_missing_prompt(missing, st)

    return {"action": "ask", "missing_keys": missing, "question": question, "errors": errors,"__src_changed": _src_changed,"__dst_changed": _dst_changed}

NUDGE_SYS = (
    "You help users configure data transfer pipelines. "
    "When the user's message has no recognizable config keys, reply with a short, empathetic nudge (max 2 sentences). "
    "Acknowledge what they said, then steer them toward sharing relevant info. "
    "Critically: reference ONLY fields still missing (provided as 'missing'). "
    "Do NOT mention schedule or start date unless they are in 'missing'. "
    "Do NOT ask for columns or transformations unless they are in 'missing' (they are optional). "
    "Never ask for secrets (hosts, ports, logins, passwords, tokens, keys). "
    "Keep it natural and context-aware."
)

MISSING_SYS = (
    "Given a list of missing configuration fields, write ONE short, natural request asking ONLY for them. "
    "Use plain English names, grouped sensibly. "
    "If 'scheduleInterval' is in missing, include choices (Daily/Weekly/Monthly/Once/@once); "
    "if 'startDate' is in missing, remind of MM/DD/YYYY. "
    "Otherwise, do NOT mention schedule or date at all. "
    "Do NOT ask for columns or transformations unless they are explicitly in 'missing'. "
    "Never ask for secrets. One or two sentences max."
)

def _nudge_and_prompt(user_text: str, st: State):
    safe_text, _ = _redact_for_llm(user_text)
    missing = _compute_missing(st)
    if not missing:
      return missing, _llm_pre_finalize_question(st)

    if _have_llm():
        try:
            nudge = _llm_contextual_nudge(safe_text, missing, st)
            ask   = _llm_missing_prompt(missing, st)
            combined = (nudge.strip() + " " + ask.strip()).strip()
            return missing, (combined if combined else ask)
        except Exception:
            pass

    return missing, "Please provide: " + ", ".join(missing)

def _llm_contextual_nudge(user_text: str, missing_fields: list, st: State) -> str:
    safe_text, _ = _redact_for_llm(user_text)
    base = "I didn’t catch any migration details yet."
    fallback = (
        f"{base} Please provide: " + ", ".join(missing_fields)
        if missing_fields else
        f"{base} Share source/destination types, names, table(s), schedule, and start date."
    )

    if not _have_llm():
        return fallback

    try:
        last_llm_payload_contains_secret = False
        _assert_no_secrets_payload()
        out = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.3,
            messages=[
                {"role": "system", "content": NUDGE_SYS},
                {"role": "user", "content": json.dumps({
                    "user_message": safe_text,
                    "missing": missing_fields[:8],
                    "state": _state_for_llm(st),
                })},
            ],
        )
        txt = (out.choices[0].message.content or "").strip()
        if not txt:
            return fallback

        def mentions(s: str, words: List[str]) -> bool:
            return any(re.search(r"\b" + re.escape(w) + r"\b", s, re.IGNORECASE) for w in words)

        if ("scheduleInterval" not in missing_fields) and mentions(txt, ["schedule","daily","weekly","monthly","@once","once"]):
            return fallback
        if ("startDate" not in missing_fields) and mentions(txt, ["start date","mm/dd/yyyy"]):
            return fallback

        cols_missing = any(w in missing_fields for w in ["sourceColumns","destColumns","transformationsSpec"])
        if (st.noColumnMap or not cols_missing) and mentions(txt, ["column","columns","transform","transformation"]):
            return fallback

        cloud_missing = any(w in missing_fields for w in [
            "sourceBucketName","sourceObjectName","sourceCloudConnType",
            "destBucketName","destObjectName","destCloudConnType"
        ])
        cloud_words = ["bucket","object name","object","cloud","cloud connection","connection type","s3","gs://","abfss","wasbs"]
        if (not cloud_missing) and mentions(txt, cloud_words):
            return fallback

        return txt
    except Exception:
        return fallback

def _llm_missing_prompt(missing_fields: list, st: State) -> str:
    fallback = "Please provide: " + ", ".join(missing_fields) if missing_fields else ""
    if not missing_fields:
        return fallback

    if _have_llm():
        try:
            last_llm_payload_contains_secret = False
            _assert_no_secrets_payload()
            out = client.chat.completions.create(
                model=OPENAI_MODEL,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": MISSING_SYS},
                    {"role": "user", "content": json.dumps({
                        "missing": missing_fields[:10],
                        "state": st.to_public_dict(),
                    })},
                ],
            )
            txt = (out.choices[0].message.content or "").strip()
            if not txt:
                return fallback

            def mentions(s: str, words: List[str]) -> bool:
                return any(re.search(r"\b" + re.escape(w) + r"\b", s, re.IGNORECASE) for w in words)

            if ("scheduleInterval" not in missing_fields) and mentions(txt, ["schedule","daily","weekly","monthly","@once","once"]):
                return fallback
            if ("startDate" not in missing_fields) and mentions(txt, ["start date","mm/dd/yyyy"]):
                return fallback
            if not any(w in missing_fields for w in ["sourceColumns","destColumns","transformationsSpec"]) and mentions(txt, ["column","columns","transform","transformation"]):
                return fallback

            cloud_missing = any(w in missing_fields for w in [
                "sourceBucketName","sourceObjectName","sourceCloudConnType",
                "destBucketName","destObjectName","destCloudConnType"
            ])
            cloud_words = ["bucket","object name","object","cloud","cloud connection","connection type","s3","gs://","abfss","wasbs"]
            if (not cloud_missing) and mentions(txt, cloud_words):
                return fallback

            return txt
        except Exception:
            pass

    return fallback

# LLM payload generator
GENERATOR_SYS = (
    "You are a schema-aware generator. Produce a SINGLE JSON object with keys "
    "creating, trigger, delete_dag, delete_conn, dbconn_source, dbconn_destination, "
    "cloudconn_source, cloudconn_destination. Use values from the provided public state. "
    "Set ALL secret fields to null (passwords, keys, tokens, hosts, ports). "
    "Use MM/DD/YYYY for dates. If an ID is unknown, set it null; the server will fill."
)
def llm_generate_payloads(state: State) -> dict:
    if PRIVACY_STRICT or not _have_llm():
        return {}
    msgs = [
        {"role": "system", "content": GENERATOR_SYS},
        {"role": "user", "content": json.dumps({"state": _state_for_llm(state)})},
    ]
    last_llm_payload_contains_secret = False
    _assert_no_secrets_payload()
    out = client.chat.completions.create(
        model=OPENAI_MODEL, temperature=0.0, response_format={"type": "json_object"}, messages=msgs
    )
    try:
        return json.loads(out.choices[0].message.content)
    except Exception:
        return {}

CONFIRM_SYS = (
    "You help users configure data transfer pipelines. "
    "Write ONE short question asking if they want to change any configuration "
    "details before collecting database/cloud connection secrets. "
    "Mention they can reply 'proceed' to continue. Max 1 sentence."
)

def _llm_pre_finalize_question(st: State) -> str:
    if _have_llm():
        try:
            last_llm_payload_contains_secret = False
            _assert_no_secrets_payload()
            out = client.chat.completions.create(
                model=OPENAI_MODEL,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": CONFIRM_SYS},
                    {"role": "user", "content": json.dumps({"state": st.to_public_dict()})},
                ],
            )
            txt = (out.choices[0].message.content or "").strip()
            if txt:
                return txt
        except Exception:
            pass
    return "Before I collect connection details, would you like to change anything? If not, reply 'proceed'."

_PROCEED_TOKENS = {
    "proceed","continue","go ahead","goahead","looks good","all good","no changes",
    "no change","nochange","done","ship it","shipit","yes","yep","ok","okay","sure"
}

def _is_proceed_intent(user_text: str) -> bool:
    s = (user_text or "").strip().lower()
    return any(tok in s for tok in _PROCEED_TOKENS)

def _print_errors_dedup(errs):
    import re as _re
    seen = set()
    for e in (errs or []):
        if e is None:
            continue
        raw = str(e).strip()
        key = _re.sub(r"\s+", " ", raw).strip().lower()
        if key in seen:
            continue
        print(f"Assistant (invalid): {raw}")
        seen.add(key)