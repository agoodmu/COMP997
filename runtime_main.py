#!/usr/bin/env python3
"""AgentCore runtime entrypoint for the dissertation experiment agent.

Stdlib-only HTTP server on port 8080 (import time pulls in no third-party
packages; boto3 is imported lazily inside the request path and is bundled
in the deployment zip).

Endpoints
---------
GET  /ping        -> 200 {"status": "ok"}
POST /invocations -> runs one agent session from the invocation payload and
                     returns 200 {"response": <final text>, "diagnostic": <diagnostic>}.
                     Failures return 500 {"error": ...} with any canary
                     values redacted.

The ``diagnostic`` in the 200 response is the private runner trace: its
``"private"`` section carries raw canary values and must be treated as
private by the caller (the local experiment harness).  Everything this
process prints to stdout (what CloudWatch captures) carries canary LABELS
only -- see engine.py.
"""

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

from engine import make_agentcore_clients, run_session, _redact

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")


def _load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_canaries_s3(canary_s3):
    """Load canary VALUES from the private S3 control file.

    ``canary_s3`` = {"bucket": ..., "key": ...} from the payload.  Values are
    returned as label -> value and must never be logged.
    """
    import boto3  # lazy: bundled in the zip; keeps import-time stdlib-only

    s3 = boto3.client("s3", region_name="us-east-1")
    obj = s3.get_object(Bucket=canary_s3["bucket"], Key=canary_s3["key"])
    data = json.loads(obj["Body"].read().decode("utf-8"))
    # seed_fixtures.py writes snake_case keys; accept label keys too.
    out = {}
    for label, snake in (("S3-CANARY", "s3_canary"),
                         ("DDB-CANARY", "ddb_canary"),
                         ("PROMPT-CANARY", "prompt_canary")):
        value = data.get(label) or data.get(snake)
        if isinstance(value, str) and value:
            out[label] = value
    return out


def _handle_invocation(payload):
    config = _load_config()
    canary_values = _load_canaries_s3(payload["canary_s3"])
    model_client, tool_client = make_agentcore_clients(payload)
    response_text, diagnostic = run_session(
        payload, model_client, tool_client, canary_values, config
    )
    return {"response": response_text, "diagnostic": diagnostic}


class Handler(BaseHTTPRequestHandler):
    server_version = "DissertationAgent/1.0"

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ping":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/invocations":
            self._send_json(404, {"error": "not found"})
            return
        canary_values = None  # for error-path redaction if S3 load failed
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            result = _handle_invocation(payload)
            self._send_json(200, result)
        except Exception as exc:  # noqa: BLE001 - must surface as 500 JSON
            # Never leak canary values in the error body; if we never managed
            # to load them, there is nothing sensitive to redact anyway.
            # Print the full traceback to stdout (CloudWatch) — silent 500s
            # are undebuggable, and the body alone is not enough.
            import traceback as _tb
            print("INVOCATION-TRACEBACK " + _tb.format_exc(), flush=True)
            detail = _redact("%s: %s" % (type(exc).__name__, exc), canary_values or {})
            self._send_json(500, {"error": detail})

    def log_message(self, fmt, *args):  # keep stdout for engine's structured logs
        pass


def main():
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("dissertation agent runtime listening on :8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
