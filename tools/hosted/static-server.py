#!/usr/bin/env python3
"""Local QA server for the generated Pages tree. Never deployed with the site."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=4173)
    args = parser.parse_args()
    root = args.directory.resolve(strict=True)
    rules = []
    if (root / "_headers").exists():
        current = None
        for line in (root / "_headers").read_text(encoding="utf-8").splitlines():
            if not line or line.lstrip().startswith("#"):
                continue
            if not line.startswith(" "):
                current = [line, []]
                rules.append(current)
            elif current is not None and ":" in line:
                name, value = line.strip().split(":", 1)
                current[1].append((name, value.strip()))

    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                if "/ /ip 302" not in (root / "_redirects").read_text(encoding="utf-8"):
                    self.send_error(500)
                    return
                self.send_response(302)
                self.send_header("Location", "/ip")
                self.end_headers()
                return
            super().do_GET()

        def end_headers(self):
            path = self.path.split("?", 1)[0]
            for pattern, headers in rules:
                if pattern == path or pattern.endswith("*") and path.startswith(pattern[:-1]):
                    for key, value in headers:
                        self.send_header(key, value)
            super().end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, directory=str(root)))
    print(f"Static preview: http://127.0.0.1:{args.port}/ip", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
