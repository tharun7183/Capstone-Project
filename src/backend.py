# backend.py
from __future__ import annotations

import os, json, uuid, queue, threading, time, builtins

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

os.environ.setdefault("SCHEMA_DIR", str(BASE_DIR))            
JSON_DIR = BASE_DIR / "json_data"
os.environ.setdefault("SAVE_DIR", str(JSON_DIR))              
JSON_DIR.mkdir(parents=True, exist_ok=True)

from typing import Dict, Optional
from fastapi import FastAPI, UploadFile, File, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

# === import your CLI chatbot module; keep FastAPI variable name "app" separate ===
import app as chatbot_app  # exposes DataTransferChatbot

# Suppress JSON body prints in UI (can turn off by exporting SUPPRESS_JSON_IN_UI=0)
SUPPRESS_JSON = os.getenv("SUPPRESS_JSON_IN_UI", "1") == "1"

# ---------- FastAPI app ----------
app = FastAPI(title="Chatbot Backend")

# CORS for local testing; lock down in prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

# ---------- Session bridge ----------
SESSIONS: Dict[str, "ChatSession"] = {}

class ChatSession:
    """
    Runs your DataTransferChatbot.chat() loop unchanged in a thread.
    We monkey-patch print/input/getpass so the UI can interact.
    """
    def __init__(self, session_id: Optional[str] = None):
        self.id = session_id or str(uuid.uuid4())
        self.bot = chatbot_app.DataTransferChatbot()

        self.out_q: "queue.Queue[dict]" = queue.Queue()
        self.in_q: "queue.Queue[str]" = queue.Queue()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.alive = True
        self._json_notice_sent = False

        # keep originals so we can restore
        self._orig_print = builtins.print
        self._orig_input = builtins.input
        try:
            import getpass as _gp
        except Exception:
            _gp = None
        self._gp_mod = _gp
        self._orig_getpass = _gp.getpass if _gp else None

    def start(self):
        self.thread.start()

    def close(self):
        self.alive = False
        try:
            self.in_q.put_nowait("")  # nudge any blocked input
        except Exception:
            pass

    def send_user_text(self, text: str):
        self.in_q.put(text)

    def _safe_put(self, payload: dict):
        try:
            self.out_q.put(payload, timeout=0.1)
        except Exception:
            pass

    def _patch_io(self):
        def patched_print(*a, **kw):
            s = " ".join(str(x) for x in a)
            if s.strip().lower() == "you:":
                return
            if SUPPRESS_JSON:
                txt = s.strip()
                looks_like_json = txt.startswith("{") or txt.startswith("[")
                is_json_header  = txt.startswith("Here is the ") or "Connection Details" in txt or txt.endswith(".json:")
                # Swallow JSON bodies and their headers; emit one friendly line once
                if looks_like_json or is_json_header:
                    if not self._json_notice_sent:
                        self._safe_put({
                            "type": "print",
                            "text": f"Assistant: All JSON files were generated and saved to {JSON_DIR}."
                        })
                        self._json_notice_sent = True
                    return

            self._safe_put({"type": "print", "text": s})

        def patched_input(prompt: str = "") -> str:
            self._safe_put({"type": "prompt", "text": prompt, "secret": False})
            return self.in_q.get()

        def patched_getpass(prompt: str = "", stream=None) -> str:
            self._safe_put({"type": "prompt", "text": prompt, "secret": True})
            return self.in_q.get()

        builtins.print = patched_print
        builtins.input = patched_input
        if self._gp_mod and self._orig_getpass:
            self._gp_mod.getpass = patched_getpass


    def _restore_io(self):
        builtins.print = self._orig_print
        builtins.input = self._orig_input
        if self._gp_mod and self._orig_getpass:
            self._gp_mod.getpass = self._orig_getpass

    def _run(self):
        try:
            self._patch_io()
            self.bot.chat()  # unchanged CLI loop
            self._safe_put({"type": "status", "event": "end"})
        except Exception as e:
            self._safe_put({"type": "error", "message": repr(e)})
        finally:
            self._restore_io()
            self.alive = False


def get_or_create_session(client_sid: Optional[str]) -> ChatSession:
    """Use the client's sessionId when possible so the UI stays attached to the same bot."""
    s = SESSIONS.get(client_sid) if client_sid else None
    if s and s.alive:
        return s
    s = ChatSession(session_id=client_sid)
    SESSIONS[s.id] = s
    s.start()
    return s


# --- Health/root so trial.html's HEAD ping turns "Connected" ---
@app.get("/")
def root():
    return {"ok": True}

@app.head("/")
def head():
    return Response(status_code=204)


# --- Simple JSON chat endpoint (matches trial.html) ---
@app.post("/chat")
async def chat(req: Request):
    data = await req.json()
    text = (data.get("message") or "").strip()
    client_sid = data.get("sessionId") or None

    s = get_or_create_session(client_sid)

    # Snapshot existing JSONs (to detect new/updated files this turn)
    t0 = time.time()
    pre = {p.name: p.stat().st_mtime for p in JSON_DIR.glob("*.json")}

    # Drain stale queue so we only return fresh output
    try:
        while True:
            s.out_q.get_nowait()
    except queue.Empty:
        pass

    # Feed the user's message
    s.send_user_text(text)

    lines: list[str] = []
    saw_prompt = False
    prompt_text = ""
    err_text = ""
    last_seen = time.time()
    deadline = time.time() + float(os.getenv("CHAT_FLUSH_SECS", "30"))

    while time.time() < deadline:
        try:
            item = s.out_q.get(timeout=0.6)
            typ = item.get("type")
            if typ == "print":
                ttxt = item.get("text", "")
                if not lines or lines[-1] != ttxt:
                    lines.append(ttxt)
                last_seen = time.time()
            elif typ == "prompt":
                saw_prompt = True
                prompt_text = (item.get("text") or "").strip()

                if prompt_text.lower() == "you:":
                    prompt_text = ""
                # NEW: drop a dangling "You:" the CLI prints just before input()
                if lines and lines[-1].strip().lower() == "you:":
                    lines.pop()

                last_seen = time.time()
                if time.time() + 0.25 > deadline:
                    deadline = time.time() + 0.25
                break
            elif typ == "error":
                err_text = item.get("message") or "unknown error"
                break
            elif typ == "status" and item.get("event") == "end":
                break
        except queue.Empty:
            if (lines or saw_prompt) and (time.time() - last_seen) > 0.7:
                break
            continue

    # Build reply
    if err_text:
        reply = f" Error: {err_text}"
        return {"reply": reply, "sessionId": s.id}

    reply = "\n".join(lines).strip()
    if saw_prompt:
        if prompt_text:
            reply = (reply + ("\n" if reply else "")) + prompt_text
        elif not reply:
            reply = "(awaiting input…)"

    # If nothing printed (e.g., JSON prints suppressed), detect saved files
    if not reply or reply == "(no output)":
        post = {p.name: p.stat().st_mtime for p in JSON_DIR.glob("*.json")}
        changed = [name for name, mt in post.items() if name not in pre or mt > pre.get(name, 0)]
        changed = [n for n in changed if post[n] >= t0 - 0.5]
        if changed:
            changed.sort()
            reply = "Assistant: JSONs generated and saved to {}\n- {}".format(JSON_DIR, "\n- ".join(changed))

    if not reply:
        reply = "(no output)"

    return {"reply": reply, "sessionId": s.id}


# --- Optional endpoints kept intact for streaming/uploads ---
@app.post("/session")
def new_session():
    s = ChatSession()
    SESSIONS[s.id] = s
    s.start()

    lines = []; prompt = ""
    t_end = time.time() + 2.0
    while time.time() < t_end:
        try:
            item = s.out_q.get(timeout=0.2)
            if item.get("type") == "print":
                t = (item.get("text") or "")
                if t.strip().lower() != "you:":
                    lines.append(t)
            elif item.get("type") == "prompt":
                prompt = (item.get("text") or "").strip()
                break
        except queue.Empty:
            break

    reply = "\n".join(lines).strip()
    if prompt.strip().lower() == "you:":
        prompt = ""
    if prompt:
        reply = (reply + ("\n" if reply else "")) + prompt
    if not reply:
        reply = "(awaiting input…)"

    return {"session_id": s.id, "reply": reply}

@app.post("/send")
def send_message(session_id: str = Form(...), text: str = Form(...)):
    s = SESSIONS.get(session_id)
    if not s or not s.alive:
        return JSONResponse({"error": "invalid or closed session"}, status_code=400)
    s.send_user_text(text)
    return {"ok": True}

@app.get("/stream/{session_id}")
def stream(session_id: str):
    s = SESSIONS.get(session_id)
    if not s:
        return JSONResponse({"error": "invalid session"}, status_code=404)

    def event_source():
        while s.alive or not s.out_q.empty():
            try:
                item = s.out_q.get(timeout=0.1)
                yield f"data: {json.dumps(item)}\n\n"
            except queue.Empty:
                yield ":\n\n"  # heartbeat
            except GeneratorExit:
                break

    return StreamingResponse(event_source(), media_type="text/event-stream")

@app.post("/upload")
async def upload_file(session_id: str = Form(...), file: UploadFile = File(...)):
    """
    Saves the file and injects 'file <path>' into the chatbot.
    Then collects the chatbot's printed output (like /chat) and returns it as reply.
    If the session was closed, it is transparently re-created with the same id.
    """
    # Auto-revive (re-create) sessions that are missing or closed
    s = get_or_create_session(session_id)

    # Save file
    upload_dir = os.environ.get("UPLOAD_DIR", "./uploads")
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = f"{uuid.uuid4()}_{file.filename}"
    path = os.path.join(upload_dir, safe_name)
    with open(path, "wb") as f:
        f.write(await file.read())
    abspath = os.path.abspath(path)

    # Snapshot JSONs to detect new/updated files
    t0 = time.time()
    pre = {p.name: p.stat().st_mtime for p in JSON_DIR.glob("*.json")}

    # Drain stale prints so we only return fresh output
    try:
        while True:
            s.out_q.get_nowait()
    except queue.Empty:
        pass

    # Inject the command your bot expects
    s.send_user_text(f"file {abspath}")

    # Collect output until prompt or quiet period
    lines, saw_prompt, prompt_text = [], False, ""
    err_text = ""
    last_seen = time.time()
    deadline = time.time() + float(os.getenv("CHAT_FLUSH_SECS", "30"))

    while time.time() < deadline:
        try:
            item = s.out_q.get(timeout=0.6)
            typ = item.get("type")
            if typ == "print":
                ttxt = item.get("text", "")
                if ttxt.strip().lower() == "you:":
                    continue
                if not lines or lines[-1] != ttxt:
                    lines.append(ttxt)
                last_seen = time.time()
            elif typ == "prompt":
                saw_prompt = True
                prompt_text = (item.get("text") or "").strip()
                if prompt_text.lower() == "you:":
                    prompt_text = ""
                if lines and lines[-1].strip().lower() == "you:":
                    lines.pop()
                last_seen = time.time()
                if time.time() + 0.25 > deadline:
                    deadline = time.time() + 0.25
                break
            elif typ == "error":
                err_text = item.get("message") or "unknown error"
                break
            elif typ == "status" and item.get("event") == "end":
                break
        except queue.Empty:
            if (lines or saw_prompt) and (time.time() - last_seen) > 0.7:
                break
            continue

    if err_text:
        return {"reply": f" Error: {err_text}", "sessionId": s.id, "path": abspath}

    # Build reply
    reply = "\n".join(lines).strip()
    if saw_prompt:
        if prompt_text:
            reply = (reply + ("\n" if reply else "")) + prompt_text
        elif not reply:
            reply = "(awaiting input…)"

    # Fallback: if nothing printed (e.g., JSONs suppressed), show files written
    if not reply or reply == "(no output)":
        post = {p.name: p.stat().st_mtime for p in JSON_DIR.glob("*.json")}
        changed = [name for name, mt in post.items() if name not in pre or mt > pre.get(name, 0)]
        changed = [n for n in changed if post[n] >= t0 - 0.5]
        if changed:
            changed.sort()
            reply = "Assistant: JSONs generated and saved to {}\n- {}".format(JSON_DIR.resolve(), "\n- ".join(changed))
        elif not reply:
            reply = "(no output)"

    return {"reply": reply, "sessionId": s.id, "path": abspath}

