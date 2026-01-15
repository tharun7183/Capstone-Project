# app.py
from __future__ import annotations
from typing import Any, Iterable, Optional, Tuple, List, Dict, Set
import os, json, re, io, uuid, ipaddress, datetime, getpass, sys, pathlib
from urllib.parse import urlparse, parse_qs, unquote
import utils
from pathlib import Path
BASE_DIR   = Path(__file__).resolve().parent
JSON_OUT   = Path(os.getenv("JSON_OUT_DIR", BASE_DIR / "json_data"))
SCHEMA_DIR = Path(os.getenv("SCHEMA_DIR",  BASE_DIR))

JSON_OUT.mkdir(parents=True, exist_ok=True)

class DataTransferChatbot:
    def __init__(self):
        self.state = utils.State()
        self.pending_keys: List[str] = []
        self.confirm_pending = False
        self._awaiting_secret_collect = False
        self._file_secret_buffer = {}
        self._awaiting_new_session = False
        self._in_finalize = False
        self._collected_runtime_secrets: Dict[str, Dict[str, str]] = {}
        self._collecting_now = False

    def _ensure_secret_store(self):
        if not hasattr(self, "_secret_store"):
            # four buckets: source/dest × db/cloud
            self._secret_store = {
                "source_db":   {},
                "dest_db":     {},
                "source_cloud":{},
                "dest_cloud":  {},
            }

    def _get_secret(self, bucket: str, key: str):
        self._ensure_secret_store()
        return self._secret_store.get(bucket, {}).get(key)

    def _store_secret(self, bucket: str, key: str, value: str):
        """Used by inline-secret capture and any other writers."""
        self._ensure_secret_store()
        if value not in (None, ""):
            self._secret_store.setdefault(bucket, {})[key] = str(value)

    def _bucket_for_side(self, is_source: bool, cloud: bool = False) -> str:
        """Maps side + medium -> bucket name."""
        return ("source_" if is_source else "dest_") + ("cloud" if cloud else "db")

    def _clear_side_secrets(self, is_source: bool):
        """Call this when a side’s type changes (e.g., MYSQL -> S3) to avoid stale creds."""
        self._ensure_secret_store()
        self._secret_store[self._bucket_for_side(is_source, False)] = {}
        self._secret_store[self._bucket_for_side(is_source, True)]  = {}


    def _apply_nonsecret_edits_if_any(self, user_text: str) -> bool:
        """
        Parse the user's line for *non-secret* config fields and apply them.
        Returns True if state was changed (so caller can refresh confirm prompt).
        """
        extracted = utils.parse_freeform(user_text)
        if not extracted:
            return False

        # Remove any secret-looking keys just in case (defensive; parse_freeform shouldn't emit secrets)
        for k in list(extracted.keys()):
            if k.lower() in {"host","port","login","password","connection_string",
                             "aws_access_key_id","aws_secret_access_key","securityToken","key_json"}:
                extracted.pop(k, None)

        before = self.state.to_public_dict().copy()
        errs = utils._apply_fields(self.state, extracted)
        utils._print_errors_dedup(errs)

        after = self.state.to_public_dict()
        changed = any(before.get(k) != after.get(k) for k in before)
        if changed:
            # If types changed, drop cached side secrets; we'll re-check later in confirm step
            if (utils._src_fp(before) != utils._src_fp(after)):
                self._clear_side_secrets(is_source=True)
            if (utils._dst_fp(before) != utils._dst_fp(after)):
                self._clear_side_secrets(is_source=False)
        return changed

    def _capture_secret_inline_and_strip_safe(self, text):
        res = self._capture_secret_inline_and_strip(text)
        if isinstance(res, tuple):
            txt = res[0]
            cap = bool(res[1]) if len(res) > 1 else False
            return txt, cap
        # If the helper ever returns just a string
        return res, False

    def _prompt_until_valid(self, label: str, validator, secret: bool = False) -> str:
        while True:
            try:
                raw = (getpass.getpass(f"  {label}: ") if secret else input(f"  {label}: "))
                raw = (raw or "").strip()
                validator(raw); return raw
            except Exception as e:
                print(f"Invalid {label}: {e}. Please try again.")

    def _prompt_optional_v(self, label: str, validator=None, error_msg: Optional[str]=None, secret: bool=False) -> Optional[str]:
        while True:
            try:
                raw = (getpass.getpass(f"  {label}: ") if secret else input(f"  {label}: "))
                raw = (raw or "").strip()
                if raw == "": return None
                if validator: validator(raw)
                return raw
            except Exception as e:
                print(f"  {error_msg or str(e)}")

    def _clear_side_secrets(self, is_source: bool):
        buckets = ("source_db", "source_cloud") if is_source else ("dest_db", "dest_cloud")
        for attr in ("file_secrets", "_file_secret_buffer", "_collected_runtime_secrets"):
            d = getattr(self, attr, {}) or {}
            for b in buckets:
                d.pop(b, None)
            setattr(self, attr, d)

    def _store_secret(self, bucket: str, key: str, value: str):
        self._file_secret_buffer.setdefault(bucket, {})[key] = value
        self._collected_runtime_secrets.setdefault(bucket, {})[key] = value

    def _bucket_for_side(self, is_source: bool) -> str:
        if is_source:
            return "source_cloud" if (self.state.sourceType in utils.CLOUD_DB_TYPES) else "source_db"
        else:
            return "dest_cloud" if (self.state.destType in utils.CLOUD_DB_TYPES) else "dest_db"

    def _capture_secret_inline_and_strip(self, user_text):
        scrubbed, found, captured = utils.parse_inline_secrets(user_text)
        for bucket, kv in (found or {}).items():
            if not kv: 
                continue
            for k, v in kv.items():
                if v:
                    self._store_secret(bucket, k, v)
        return scrubbed, bool(captured)

    def _reset_secret_caches(self, reason: str = "reset"):
        self.file_secrets = {}
        self._file_secret_buffer = {}
        self._collected_runtime_secrets = {}

    def _assign_value_only_to_pending(self, text: str) -> List[str]:
        errors: List[str] = []
        raw = (text or "").strip()
        if not raw:
            return errors

        extracted = utils.parse_freeform(raw)
        if extracted:
            errs = utils._apply_fields(self.state, extracted)
            errors.extend(errs)
            self.pending_keys = utils._compute_missing(self.state)
            return errors

        tokens = [t.strip() for t in re.split(r"(?:,|;|\s+and\s+)", raw) if t.strip()]
        if not tokens:
            return errors

        for i, key in enumerate(self.pending_keys):
            if i >= len(tokens):
                break
            new_val, err = utils.try_capture_field(key, tokens[i])
            if new_val is None:
                errors.append(f"{key}: {err or 'Invalid'}")
                continue
            if key == "sourceColumns" and new_val == "__NO_COLUMN_MAP__":
                self.state.noColumnMap = True
                self.state.sourceColumns = self.state.destColumns = self.state.transformationsSpec = None
                continue
            setattr(self.state, key, new_val if new_val != "" else None)

        fix = utils._consistency_or_error(self.state)
        if fix:
            errors.append(f"columns: {fix}")

        self.pending_keys = utils._compute_missing(self.state)
        return errors

    def _prefill_from_file(self, side_label: str) -> Dict[str, Optional[str]]:
        buf = getattr(self, "_file_secret_buffer", {}) or getattr(self, "file_secrets", {}) or {}
        is_source = side_label.upper().startswith("SOURCE")

        if (is_source and (self.state.sourceType or '').upper() in utils.DB_TYPES_CANON) or ((not is_source) and (self.state.destType or '').upper() in utils.DB_TYPES_CANON):
            return dict(buf.get("source_db" if is_source else "dest_db", {}))

        if (is_source and self.state.sourceType in utils.CLOUD_DB_TYPES) or ((not is_source) and self.state.destType in utils.CLOUD_DB_TYPES):
            return dict(buf.get("source_cloud" if is_source else "dest_cloud", {}))

        return {}

    def _secrets_complete_for_state(self, use: dict | None = None) -> bool:
        """Decide if secrets are complete using the *given* dict (prefill) if provided.
        This mirrors latest.py behavior and avoids relying on stale self.file_secrets."""
        pre = dict(use or (getattr(self, "file_secrets", {}) or {}))
        missing = utils._compute_missing_secrets_from_state(self.state, pre)
        return not bool(missing)

    def _confirm_text(self) -> str:
        missing_cfg = utils._compute_missing(self.state)
        if missing_cfg:
            return utils._llm_missing_prompt(missing_cfg, self.state)

        fs = getattr(self, "file_secrets", {}) or {}
        utils._fill_secrets_from_conn_strings_in_place(self.state, fs)  # ← critical
        self.file_secrets = fs

        ms = utils._compute_missing_secrets_from_state(self.state, fs)
        if ms:
            sides = []
            if ms.get("source_db") or ms.get("source_cloud"):
                sides.append("SOURCE")
            if ms.get("dest_db") or ms.get("dest_cloud"):
                sides.append("DESTINATION")
            side_txt = " and ".join(sides) if sides else "SOURCE/DESTINATION"
            return (f"Configuration details looks good. Reply 'proceed' to enter the missing {side_txt} secret fields only, "
                    "or Do you want to change any configuration details.")

        return "Everything looks good. Reply 'proceed' to generate the JSONs, or Do you want to change any configuration details."

    def _show_confirm_once(self):
        if not self.confirm_pending:
            print("Assistant:", self._confirm_text())
            self.confirm_pending = True

    def _finalize_now(self):
        if self._in_finalize:
            return
        self._in_finalize = True
        try:
            prefill = self._merge_secrets(
                getattr(self, "file_secrets", {}) or {},
                getattr(self, "_file_secret_buffer", {}) or {},
            )
            self._finalize_and_save(secrets_from_file=prefill)
            print("\nAssistant: Done. Start another? (type 'exit' to quit)")
            self._reset_secret_caches("finalized")
            self.state = utils.State()
            self.confirm_pending = False
            self._awaiting_secret_collect = False
            self._awaiting_new_session = True
        finally:
            self._in_finalize = False

    def _merge_secrets(self, a: dict, b: dict) -> dict:
        buckets = {"source_db": {}, "dest_db": {}, "source_cloud": {}, "dest_cloud": {}}
        out = {k: {} for k in buckets}
        for src in (a or {}), (b or {}):
            for bk in out:
                if isinstance(src.get(bk), dict):
                    for k, v in src[bk].items():
                        if v not in (None, ""):
                            out[bk][k] = v
        return out

    def _collect_db_secrets(self,side_label: str,default_port_hint: Optional[int],db_type: Optional[str] = None,pre_override: Optional[dict] = None) -> dict:
          # cache bucket key
          cache_key = "source_db" if side_label.upper().startswith("SOURCE") else "dest_db"
          if cache_key in self._collected_runtime_secrets:
              return dict(self._collected_runtime_secrets[cache_key])

          # 1) prefill: file → cache (none yet) → override
          pre_from_file = self._prefill_from_file(side_label) or {}
          vals: Dict[str, Optional[str]] = {
              "connection_string": None,
              "host": None,
              "port": None,
              "login": None,
              "password": None,
              "database": None,
          }
          # file first
          for k in list(vals.keys()):
              v = pre_from_file.get(k)
              if v not in (None, ""):
                  vals[k] = v
          # override next
          if pre_override:
              for k, v in pre_override.items():
                  if v not in (None, ""):
                      vals[k] = v
          # merge inline (if you saved secrets via _store_secret earlier)
          bucket_name = "source_db" if side_label.upper().startswith("SOURCE") else "dest_db"
          for k in ("connection_string", "host", "port", "login", "password", "database"):
              if not vals.get(k):
                  v = self._get_secret(bucket_name, k)
                  if v:
                      vals[k] = v

          # 2) parse connection string (if any)
          dt = (db_type or (self.state.sourceType if side_label.upper().startswith("SOURCE") else self.state.destType) or "").upper()
          if vals.get("connection_string"):
              try:
                  parts = utils.validate_db_connection_string(dt, vals["connection_string"])
                  vals["host"]     = vals["host"]     or parts.get("host")
                  vals["port"]     = (vals["port"]  or parts.get("port") or (str(utils.DEFAULT_PORTS.get(dt)) if utils.DEFAULT_PORTS.get(dt) else None))
                  vals["login"]    = vals["login"]    or parts.get("login")
                  vals["password"] = vals["password"] or parts.get("password")
                  # database/service_name extraction
                  if dt in {"MYSQL", "PSQL", "MSSQL"} and parts.get("database"):
                      vals["database"] = vals["database"] or parts.get("database")
                  if dt == "ORACLE" and parts.get("service_name"):
                      vals["database"] = vals["database"] or parts.get("service_name")
              except Exception as e:
                  print(f"  {side_label} connection_string from file is invalid: {e}")

          # 3) Short-circuit only if the four basics are VALID (not just present)
          if utils._secrets_valid_db(vals):
              self._collected_runtime_secrets[cache_key] = dict(vals)
              return dict(vals)

          # 4) validate any present fields; drop bad ones so we re-prompt only for those
          def _try(v, fn):
              try:
                  fn(v); return True
              except Exception:
                  return False

          invalid = []
          if vals.get("host") and not _try(vals["host"], utils.validate_host): invalid.append("host"); vals["host"] = None
          if vals.get("port") and not _try(vals["port"], utils.validate_port): invalid.append("port"); vals["port"] = None
          if vals.get("login") and not _try(vals["login"], lambda x: utils.validate_non_empty("login", x)): invalid.append("login"); vals["login"] = None
          if vals.get("password") and not _try(vals["password"], lambda x: utils.validate_non_empty("password", x)): invalid.append("password"); vals["password"] = None
          if invalid:
              print(f"  Ignoring invalid {side_label} {', '.join(invalid)} from file;")

          # 5) if nothing present AND no conn string, offer a one-shot conn string first
          basics = ("host", "port", "login", "password")
          if not vals.get("connection_string") and all(not vals.get(k) for k in basics):
              try:
                  conn_str = input(f"  {side_label} connection string (optional; press Enter to skip): ").strip()
              except EOFError:
                  conn_str = ""
              if conn_str:
                  try:
                      parts = utils.validate_db_connection_string(dt, conn_str)
                      vals["host"]     = vals["host"]     or parts.get("host")
                      vals["port"]     = vals["port"]     or parts.get("port")
                      vals["login"]    = vals["login"]    or parts.get("login")
                      vals["password"] = vals["password"] or parts.get("password")
                  except Exception as e:
                      print(f"  Invalid connection string: {e}. We'll ask individual fields.")

          # 6) prompt only for missing basics (unchanged prompt style)
          present = [k for k in basics if vals.get(k)]
          missing = [k for k in basics if not vals.get(k)]
          if present and missing:
              print(f"  Using {side_label} {', '.join(present)} from file; asking only: {', '.join(missing)}.")
          elif missing:
              print(f"  Need {side_label} {', '.join(missing)}.")

          # host
          if "host" in missing:
              vals["host"] = self._prompt_until_valid(f"{side_label} host", utils.validate_host, secret=False)

          # port (default: utils.DEFAULT_PORTS or fallback to default_port_hint)
          if "port" in missing:
              default_port = utils.DEFAULT_PORTS.get(dt) or (str(default_port_hint) if default_port_hint else "")
              try:
                  raw = input(f"  {side_label} port (1..65535, Enter for default {default_port}): ").strip()
              except EOFError:
                  raw = ""
              if raw == "" and default_port:
                  vals["port"] = str(default_port)
              else:
                  try:
                      utils.validate_port(raw); vals["port"] = raw
                  except Exception as e:
                      print(f"Invalid port: {e}.")
                      vals["port"] = self._prompt_until_valid(f"{side_label} port (1..65535)", utils.validate_port, secret=False)

          # login
          if "login" in missing:
              vals["login"] = self._prompt_until_valid(f"{side_label} login", lambda v: utils.validate_non_empty("login", v), secret=False)

          # password
          if "password" in missing:
              vals["password"] = self._prompt_until_valid(f"{side_label} password", lambda v: utils.validate_non_empty("password", v), secret=True)

          # 7) cache + return
          self._collected_runtime_secrets[cache_key] = dict(vals)
          return dict(vals)

    def _collect_cloud_secrets(self, side_label: str, conn_type_text: str, pre_override: Optional[dict] = None) -> dict:
        cache_key = "source_cloud" if side_label.upper().startswith("SOURCE") else "dest_cloud"
        if cache_key in self._collected_runtime_secrets:
            return dict(self._collected_runtime_secrets[cache_key])

        # --- 1) prefill ---
        pre_from_file = self._prefill_from_file(side_label) or {}
        # ensure we have all keys covered (even if CLOUD_OPTIONAL_FIELDS is missing some)
        all_cloud_keys = set(getattr(utils, "CLOUD_OPTIONAL_FIELDS", [])) | {
            "connection_string", "bucket_name", "container_name", "region_name", "securityToken",
            "login", "password", "aws_access_key_id", "aws_secret_access_key", "key_json"
        }
        out: Dict[str, Optional[str]] = {k: None for k in all_cloud_keys}

        # file → override
        for k in out.keys():
            v = pre_from_file.get(k)
            if v not in (None, ""):
                out[k] = v
        if pre_override:
            for k, v in pre_override.items():
                if v not in (None, ""):
                    out[k] = v

        # convenience default for bucket name
        if side_label.upper().startswith("DEST"):
            out["bucket_name"] = out["bucket_name"] or getattr(self.state, "destBucketName", None)
        else:
            out["bucket_name"] = out["bucket_name"] or getattr(self.state, "sourceBucketName", None)

        printed = False
        def _header():
            nonlocal printed
            if not printed:
                print(f"Enter {side_label} CLOUD connection details (kept local, NOT sent to OpenAI). Type hint: {conn_type_text}.")
                printed = True

        def _take_optional(key, label, validator=None, hide=False, error_msg=None):
            v = out.get(key)
            if v not in (None, ""):
                try:
                    if validator: validator(v)
                    return
                except Exception as e:
                    print(f"  {label} from file is invalid: {e}.")
                    out[key] = None
            _header()
            try:
                raw = (getpass.getpass(f"  {side_label} {label} (optional): ") if hide else input(f"  {side_label} {label} (optional): ")).strip()
            except EOFError:
                raw = ""
            if raw == "":
                return
            try:
                if validator: validator(raw)
                out[key] = raw
            except Exception as e:
                print(f"  {error_msg or str(e)}")

        def _take_required(key, label, validator=None, hide=False, error_msg=None):
            v = out.get(key)
            if v not in (None, ""):
                try:
                    if validator: validator(v)
                    return
                except Exception as e:
                    print(f"  {label} from file is invalid: {e}.")
                    out[key] = None
            while True:
                _header()
                try:
                    raw = (getpass.getpass(f"  {side_label} {label} (required): ") if hide else input(f"  {side_label} {label} (required): ")).strip()
                except EOFError:
                    raw = ""
                if raw == "":
                    print(f"  {label} is required.")
                    continue
                try:
                    if validator: validator(raw)
                    out[key] = raw
                    return
                except Exception as e:
                    print(f"  {error_msg or str(e)}")

        # --- 2) collect (connection_string now OPTIONAL) ---
        _take_optional("connection_string", "connection_string", utils._v_cloud_connstr,
                      error_msg="Unsupported scheme: use s3://, gs://, abfss://, or wasbs://")
        _take_optional("bucket_name", "bucket_name",
                      lambda v: utils.BUCKET_RE.fullmatch(v) or (_ for _ in ()).throw(ValueError("Bucket: lowercase 3–63, dots/hyphens ok.")))
        _take_optional("container_name", "container_name",
                      lambda v: utils.AZURE_CONTAINER_RE.fullmatch(v) or (_ for _ in ()).throw(ValueError("Container: lowercase 3–63, hyphens ok.")))
        _take_optional("region_name", "region_name",
                      lambda v: utils.AWS_REGION_RE.fullmatch(v) or (_ for _ in ()).throw(ValueError("Region must look like 'us-east-1'.")))
        _take_optional("securityToken", "securityToken")
        _take_optional("key_json", "key_json", lambda v: json.loads(v) or True,
                      error_msg="key_json must be valid JSON text.")
        _take_optional("aws_access_key_id", "aws_access_key_id",
                      lambda v: utils.AWS_ACCESS_KEY_ID_RE.fullmatch(v) or (_ for _ in ()).throw(ValueError("AWS Access Key ID must be 20 uppercase letters/digits.")))
        _take_optional("aws_secret_access_key", "aws_secret_access_key",
                      lambda v: utils.AWS_SECRET_ACCESS_KEY_RE.fullmatch(v) or (_ for _ in ()).throw(ValueError("AWS Secret must be 40 valid chars.")),
                      hide=True)

        # Make login/password REQUIRED (your requirement)
        _take_required("login", "login")  # accept any non-empty; provider-specific regex is optional
        _take_required("password", "password", hide=True)

        # --- 3) small normalization / mapping ---
        # Trim common trailing typo in connection strings
        if out.get("connection_string"):
            out["connection_string"] = out["connection_string"].rstrip(";").strip()
            try:
                utils._v_cloud_connstr(out["connection_string"])
            except Exception as e:
                print(f"  {side_label} connection_string invalid: {e}")

        # If this looks like S3 and aws_* are empty, map login/password → aws_* for downstream compatibility
        kind = (conn_type_text or "").strip().upper()
        if "S3" in kind or "AWS" in kind:
            if not out.get("aws_access_key_id") and out.get("login"):
                out["aws_access_key_id"] = out["login"]
            if not out.get("aws_secret_access_key") and out.get("password"):
                out["aws_secret_access_key"] = out["password"]
            # Validate if present
            if out.get("aws_access_key_id") and not utils.AWS_ACCESS_KEY_ID_RE.fullmatch(out["aws_access_key_id"]):
                print("  AWS Access Key ID format looks invalid.")
            if out.get("aws_secret_access_key") and not utils.AWS_SECRET_ACCESS_KEY_RE.fullmatch(out["aws_secret_access_key"]):
                print("  AWS Secret Access Key format looks invalid.")

        # Final soft sanity (doesn’t block; just surfaces issues)
        try:
            if out.get("bucket_name") and not utils.BUCKET_RE.fullmatch(out["bucket_name"]):
                raise ValueError("Invalid bucket_name format.")
            if out.get("container_name") and not utils.AZURE_CONTAINER_RE.fullmatch(out["container_name"]):
                raise ValueError("Invalid container_name format.")
            if out.get("region_name") and not utils.AWS_REGION_RE.fullmatch(out["region_name"]):
                raise ValueError("Invalid region_name format.")
            if out.get("key_json"):
                json.loads(out["key_json"])
        except Exception as e:
            print(f"  {side_label} cloud details look invalid: {e}")

        # --- 4) cache & return ---
        self._collected_runtime_secrets[cache_key] = dict(out)
        return dict(out)

    def _collect_secrets_both_sides(self, prefill: dict | None = None) -> dict:
        if self._collecting_now:
            return {}
        self._collecting_now = True
        try:
            prefill = dict(prefill or {})
            # SHORT-CIRCUIT: if prefill already satisfies the state, skip prompts entirely
            if prefill and self._secrets_complete_for_state(prefill):
                # also stash in runtime cache so downstream masks/logs still work
                for bucket, blk in (prefill or {}).items():
                    if isinstance(blk, dict):
                        self._collected_runtime_secrets[bucket] = dict(blk)
                return dict(prefill)

            out = {}

            # SOURCE
            if (self.state.sourceType or '').upper() in utils.DB_TYPES_CANON:
                pf = prefill.get("source_db") or {}
                if utils._secrets_valid_db(pf):
                    out["source_db"] = dict(pf)
                    self._collected_runtime_secrets["source_db"] = dict(pf)
                else:
                    out["source_db"] = self._collect_db_secrets(
                        "SOURCE", utils.DEFAULT_PORTS.get(self.state.sourceType),
                        db_type=self.state.sourceType, pre_override=pf
                    )
            elif self.state.sourceType in utils.CLOUD_DB_TYPES:
                pf = prefill.get("source_cloud") or {}
                if pf:
                    self._collected_runtime_secrets["source_cloud"] = dict(pf)
                out["source_cloud"] = self._collect_cloud_secrets(
                    "SOURCE", self.state.sourceCloudConnType or self.state.sourceType
                )

            # DEST
            if (self.state.destType or '').upper() in utils.DB_TYPES_CANON:
                pf = prefill.get("dest_db") or {}
                if utils._secrets_valid_db(pf):
                    out["dest_db"] = dict(pf)
                    self._collected_runtime_secrets["dest_db"] = dict(pf)
                else:
                    out["dest_db"] = self._collect_db_secrets(
                        "DESTINATION", utils.DEFAULT_PORTS.get(self.state.destType),
                        db_type=self.state.destType, pre_override=pf
                    )
            elif self.state.destType in utils.CLOUD_DB_TYPES:
                pf = prefill.get("dest_cloud") or {}
                if pf:
                    self._collected_runtime_secrets["dest_cloud"] = dict(pf)
                out["dest_cloud"] = self._collect_cloud_secrets(
                    "DESTINATION", self.state.destCloudConnType or self.state.destType
                )

            return out
        finally:
            self._collecting_now = False

    def _finalize_and_save(self, secrets_from_file: Optional[dict] = None) -> bool:
        self._collected_runtime_secrets = {}

        if self.state.sourceColumns not in (None, ""):
            fix = utils._consistency_or_error(self.state)
            if fix:
                print(f"Assistant: {fix}")
                return False
        else:
            self.state.noColumnMap = True

        missing_cfg = utils._compute_missing(self.state)
        if missing_cfg:
            print("Assistant:", utils._llm_missing_prompt(missing_cfg, self.state))
            return False

        prefill = self._merge_secrets(
            getattr(self, "file_secrets", {}) or {},
            getattr(self, "_file_secret_buffer", {}) or {},
        )
        utils._fill_secrets_from_conn_strings_in_place(self.state, prefill)

        utils._fill_secrets_from_conn_strings_in_place(self.state, prefill)
        collected = self._collect_secrets_both_sides(prefill=prefill)

        draft = {}
        if utils._have_llm() and not utils.PRIVACY_STRICT:
            try:
                draft = llm_generate_payloads(self.state)
            except Exception as e:
                print(f"Assistant: Failed to get JSON draft from OpenAI: {e}")

        creating, trigger, delete_dag, delete_conn, src_conns, dst_conns = utils.fill_ids_and_secrets(
            draft, self.state, collected
        )
        (db_source, cloud_source) = src_conns
        (db_dest,   cloud_dest)   = dst_conns
        #print("DEBUG MAPPING:", self.state.sourceColumns, self.state.destColumns, self.state.transformationsSpec, "noMap?", self.state.noColumnMap)

        utils.avro_validate_or_raise("creating", creating); utils.custom_validation_rules("creating", creating)
        utils.avro_validate_or_raise("trigger",  trigger ); utils.custom_validation_rules("trigger",  trigger)
        if "delete_dag"  in utils.SCHEMAS and delete_dag:  utils.avro_validate_or_raise("delete_dag",  delete_dag)
        if "delete_conn" in utils.SCHEMAS and delete_conn: utils.avro_validate_or_raise("delete_conn", delete_conn)

        utils._save_json_file(os.path.join(utils.SAVE_DIR,"CreatingDag.json"), creating)
        utils._save_json_file(os.path.join(utils.SAVE_DIR,"TriggerDag.json"),  trigger)
        if delete_dag:  utils._save_json_file(os.path.join(utils.SAVE_DIR,"DeleteDag.json"), delete_dag)
        if delete_conn: utils._save_json_file(os.path.join(utils.SAVE_DIR,"DeleteConnection.json"), delete_conn)

        def _save_conn_json(details: dict, fallback_name: str):

            fname = f"{(details or {}).get('conn_id')}.json" if (details or {}).get("conn_id") else fallback_name
            utils._save_json_file(os.path.join(utils.SAVE_DIR, fname), details)

        if db_source:
            utils.avro_validate_or_raise("dbconn", db_source); utils.custom_validation_rules("dbconn", db_source)
            _save_conn_json(db_source, "Database_connection_details_source.json")

        if cloud_source:
            utils.avro_validate_or_raise("cloudconn", cloud_source); utils.custom_validation_rules("cloudconn", cloud_source)
            _save_conn_json(cloud_source, "Cloud_connection_details_source.json")

        if db_dest:
            utils.avro_validate_or_raise("dbconn", db_dest); utils.custom_validation_rules("dbconn", db_dest)
            _save_conn_json(db_dest, "Database_connection_details_destination.json")

        if cloud_dest:
            utils.avro_validate_or_raise("cloudconn", cloud_dest); utils.custom_validation_rules("cloudconn", cloud_dest)
            _save_conn_json(cloud_dest, "Cloud_connection_details_destination.json")

        def _mask(d: Optional[dict]) -> Optional[dict]:
            if not d: return d
            m=dict(d)
            for k in ("password","aws_secret_access_key","securityToken"):
                if k in m and isinstance(m[k], str) and m[k]:
                    m[k] = "*" * len(m[k])
            return m

        print("Here is the CreatingDag JSON:"); print(json.dumps(creating, indent=4))
        print("\nHere is the TriggerDag JSON:"); print(json.dumps(trigger, indent=4))
        if delete_dag:  print("\nHere is the DeleteDag JSON:"); print(json.dumps(delete_dag, indent=4))
        if delete_conn: print("\nHere is the DeleteConnection JSON:"); print(json.dumps(delete_conn, indent=4))
        if db_source:   print("\nHere are the Connection Details for SOURCE Database:"); print(json.dumps(_mask(db_source), indent=4))
        if cloud_source:print("\nHere are the Connection Details for SOURCE Cloud:");   print(json.dumps(_mask(cloud_source), indent=4))
        if db_dest:     print("\nHere are the Connection Details for DESTINATION Database:"); print(json.dumps(_mask(db_dest), indent=4))
        if cloud_dest:  print("\nHere are the Connection Details for DESTINATION Cloud:");   print(json.dumps(_mask(cloud_dest), indent=4))

        return True

    def chat(self):
      if not utils._have_llm():
          print("WARNING: OPENAI_API_KEY is not set. Running in local NLP fallback mode.")
      print("Assistant: Hello! I can help you create data-transfer JSONs (DB or Cloud, both sides). Let's begin. Type 'exit' to quit.")
      while True:
          user = input("You: ").strip()

          # capture secrets (never send to LLM) and scrub the turn text
          user, _captured_secret = self._capture_secret_inline_and_strip_safe(user)
          if _captured_secret:
              print("Assistant: Noted the secure detail(s).")
          _cap = self._capture_secret_inline_and_strip(user)
          if isinstance(_cap, tuple):
              user_sanitized = _cap[0]
              captured = bool(_cap[1]) if len(_cap) > 1 else False
          else:
              user_sanitized = _cap
              captured = False

          if captured:
              print("Assistant: Noted the secure detail(s).")
              user = user_sanitized

          if utils._is_proceed_intent(user) and not utils._compute_missing(self.state):
            if not self.confirm_pending:
                self.confirm_pending = True
                print("Assistant:", self._confirm_text())
                continue

          if user.lower() in {"exit","quit"}:
              print("Assistant: Goodbye!")
              break
          if user.lower().startswith("file "):
              raw_path = user[5:].strip()
              if (raw_path.startswith(("'", '"')) and raw_path.endswith(("'", '"')) and len(raw_path) >= 2):
                  raw_path = raw_path[1:-1]
              path = os.path.expanduser(raw_path)
              self._reset_secret_caches("new-file")
              try:
                  file_fields, file_secrets, file_errs = utils._file_read_and_split(path)
                  #print("DEBUG file sourceDatabase =", repr((file_fields or {}).get("sourceDatabase")))
              except Exception as e:
                  print(f"Assistant: Failed to load file: {e}")
                  continue

              errs = utils._validate_file_fields_and_apply(self.state, file_fields)
              secret_errs = []
              for side in ("source_db","dest_db","source_cloud","dest_cloud"):
                  blk = (file_secrets or {}).get(side) or {}
                  if blk:
                      secret_errs += utils._validate_secret_block(self.state, side, blk)

              utils._print_errors_dedup((file_errs or []) + (errs or []) + (secret_errs or []))


              self._file_secret_buffer = file_secrets or {}
              self.file_secrets = file_secrets or {}
              print("Assistant:", self._confirm_text())
              self.confirm_pending = True
              continue
              missing_now = utils._compute_missing(self.state)
              if missing_now:
                  print("Assistant:", utils._llm_missing_prompt(missing_now, self.state))
                  self.pending_keys = missing_now
                  self.confirm_pending = False
              else:
                  self.confirm_pending = True
              continue

          if utils._is_proceed_intent(user):
              if utils._compute_missing(self.state):
                  print("Assistant:", utils._llm_missing_prompt(utils._compute_missing(self.state), self.state))
                  self.confirm_pending = False
              else:
                  self._finalize_now()
              continue

          if self.confirm_pending:
            # Allow non-secret config edits here without changing the flow
            if user and not _captured_secret:
                if self._apply_nonsecret_edits_if_any(user):
                    print("Assistant:", self._confirm_text())
                    continue

            # If secrets were pasted during confirm, we simply acknowledge and refresh
            if _captured_secret:
                print("Assistant:", self._confirm_text())
                continue
            user_sanitized, captured = self._capture_secret_inline_and_strip_safe(user)
            if captured:
                print("Assistant: Updated the secure detail(s). Reply 'proceed' to continue or add more edits.")
                # Show updated confirm prompt (it will reflect which sides still need anything)
                print("Assistant:", self._confirm_text())
                continue
            if utils._is_proceed_intent(user):

                self._in_finalize = True
                try:
                    prefill = self._merge_secrets(
                        getattr(self, "file_secrets", {}) or {},
                        getattr(self, "_file_secret_buffer", {}) or {}
                    )
                    #print("DEBUG prefill source_db =", prefill.get("source_db"))
                    self._finalize_and_save(secrets_from_file=prefill)
                    print("\nAssistant: Done. Start another? (type 'exit' to quit)")
                    self.state = utils.State()
                    self.confirm_pending = False
                    self._awaiting_secret_collect = False
                    self._file_secret_buffer = {}
                finally:
                    self._in_finalize = False
                continue

            mapping_keys = {"sourceColumns", "destColumns", "transformationsSpec"}
            extracted = utils.parse_freeform(user)

            if any(k in extracted for k in mapping_keys):
                _before = self.state.to_public_dict().copy()
                errs = utils._apply_fields(self.state, extracted)
                _after = self.state.to_public_dict()

                if utils._src_fp(_before) != utils._src_fp(_after):
                    self._clear_side_secrets(is_source=True)
                if utils._dst_fp(_before) != utils._dst_fp(_after):
                    self._clear_side_secrets(is_source=False)

                utils._print_errors_dedup(errs)
                print("Assistant: Column mapping noted. Reply 'proceed' to continue or add more edits.")
                continue

            if re.search(r'\b(source\s*columns?|dest(?:ination)?\s*columns?|transformation(?:s)?\s*spec|transformations?spec)\b',
                        user, re.IGNORECASE):
                print("Assistant (invalid): I couldn’t parse the column mapping. Try e.g. "
                      "\"source columns: id,name\" and \"destination columns: id,name\"; "
                      "optionally \"transformation spec: lower|trim\".")
                continue
            print("Assistant:", utils._llm_pre_finalize_question(self.state))
            continue

            extracted = utils.parse_freeform(user)
            if extracted:
                _before = self.state.to_public_dict().copy()
                errs = utils._apply_fields(self.state, extracted)
                _after = self.state.to_public_dict()

                if utils._src_fp(_before) != utils._src_fp(_after):
                    self._clear_side_secrets(is_source=True)
                if utils._dst_fp(_before) != utils._dst_fp(_after):
                    self._clear_side_secrets(is_source=False)
                utils._print_errors_dedup(errs)

                missing = utils._compute_missing(self.state)
                if missing:
                    print("Assistant:", utils._llm_missing_prompt(missing, self.state))
                    self.pending_keys = missing
                else:
                    self._show_confirm_once()
                continue

          if self.pending_keys:
              errs = self._assign_value_only_to_pending(user)
              if errs:
                  bad = [e.split(":")[0] for e in errs]
                  self.pending_keys = [k for k in self.pending_keys if k in bad] or self.pending_keys
                  print("Assistant (invalid): " + "; ".join(errs))
              missing_now = utils._compute_missing(self.state)
              if missing_now:
                  self.pending_keys = missing_now
                  print("Assistant:", utils._llm_missing_prompt(missing_now, self.state))
                  continue
              else:
                  self._show_confirm_once()
                  self.pending_keys = []
                  continue

          norm = user.strip().lower()

          if self._awaiting_new_session:
              if norm in {"yes","y","ok","okay","start","sure"}:
                  print("Assistant: Great — tell me the new setup: source/destination types & names, tables, schedule (Daily/Weekly/Monthly/Once/@once), and start date (MM/DD/YYYY).")
                  self._awaiting_new_session = False
                  continue
              if norm in {"no","n","exit","quit"}:
                  print("Assistant: Goodbye!")
                  break
              self._awaiting_new_session = False

          if (self._awaiting_secret_collect and not self.confirm_pending and norm in {"proceed","ok","okay","continue","go","yes","y"}):
              if norm in ACK_TOKENS:
                  def _merge(a, b):
                      out = {"source_db": {}, "dest_db": {}, "source_cloud": {}, "dest_cloud": {}}
                      for bucket in out:
                          if isinstance(a.get(bucket), dict): out[bucket].update(a[bucket])
                          if isinstance(b.get(bucket), dict):
                              for k, v in b[bucket].items():
                                  out[bucket].setdefault(k, v)
                      return out

                  merged_prefill = _merge(getattr(self, "file_secrets", {}) or {},
                                          getattr(self, "_file_secret_buffer", {}) or {})

                  self._finalize_and_save(secrets_from_file=merged_prefill)
                  print("\nAssistant: Done. Start another? (type 'exit' to quit)")
                  self.state = utils.State()
                  self._awaiting_secret_collect = False
                  self._file_secret_buffer = {}
                  continue

              if norm in CANCEL_TOKENS:
                  print("Assistant: Sure—what would you like to change? You can retype any fields (e.g., 'dest db toy2' or 'schedule weekly').")
                  self._awaiting_secret_collect = False
                  continue
          elif self._awaiting_secret_collect and norm in {"change","edit","modify","update","no","n"}:
              print("Assistant:", utils._llm_missing_prompt(utils._compute_missing(self.state), self.state))
              self._awaiting_secret_collect = False
              continue

          quick_errs = utils._quick_bind_single_value(self.state, user)
          if quick_errs:
              utils._print_errors_dedup(quick_errs)

          step = utils._llm_step(self.state, user)
          if step.get("__src_changed"):
              self._clear_side_secrets(is_source=True)
          if step.get("__dst_changed"):
              self._clear_side_secrets(is_source=False)

          errs=step.get("errors", [])
          utils._print_errors_dedup(errs)

          if step.get("action") == "ask":
              q = step.get("question") or f"Please provide: {', '.join(step.get('missing_keys', []))}"
              print("Assistant:", q)
              self.pending_keys = list(step.get("missing_keys", []) or utils._compute_missing(self.state))
              self.confirm_pending = False
              continue

          if step.get("action") == "finalize":
              self._show_confirm_once()
              self._awaiting_secret_collect = False
              continue


if __name__ == "__main__":
    bot = DataTransferChatbot()
    bot.chat()