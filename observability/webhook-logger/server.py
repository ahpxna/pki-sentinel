#!/usr/bin/env python3
"""Minimal webhook receiver used as the Alertmanager fallback receiver when
SLACK_WEBHOOK_URL is unset. Logs every alert payload to stdout so
`docker compose logs webhook-logger` demonstrates the alert path end-to-end
without a real Slack workspace."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            for alert in payload.get("alerts", []):
                name = alert.get("labels", {}).get("alertname", "unknown")
                status = alert.get("status", "unknown")
                summary = alert.get("annotations", {}).get("summary", "")
                print(f"[webhook-logger] alert={name} status={status} summary={summary}", flush=True)
        except json.JSONDecodeError:
            print(f"[webhook-logger] non-JSON payload: {body!r}", flush=True)
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # Suppress default access logging; alert payloads are logged above.


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
