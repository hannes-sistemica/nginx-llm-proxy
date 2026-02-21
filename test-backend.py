#!/usr/bin/env python3
"""
Dummy OpenAI-compatible backend for testing llm-proxy.
Echoes back the port it's running on and the requested model name.

Usage: python3 test-backend.py <port>
"""
import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9090


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if "/embeddings" in self.path:
            resp = {
                "object": "list",
                "model": f"dummy-embed-{PORT}",
                "data": [{
                    "object": "embedding",
                    "index": 0,
                    "embedding": [0.1, 0.2, 0.3]
                }],
                "usage": {"prompt_tokens": 1, "total_tokens": 1}
            }
        else:
            resp = {
                "id": "test-123",
                "object": "chat.completion",
                "model": f"dummy-chat-{PORT}",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Hello from port {PORT}! "
                                   f"Model: {body.get('model', '?')}"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 10,
                    "total_tokens": 11
                }
            }

        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(out))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        resp = json.dumps({"status": "ok", "port": PORT}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(resp))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"Test backend on :{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
