"""Run a temporary localhost HTTP demo and compare vulnerable/hardened modes.

Uses no real accounts or secrets. Each server binds only to 127.0.0.1 on an
ephemeral port, is assessed by this process, and shuts down before exit.
This is an HTTP behavior exercise, not a production-ready application.
"""
import argparse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler


@contextmanager
def demo_server(hardened=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            status = 404 if self.path == "/debug" and hardened else 200
            if self.path == "/debug" and not hardened:
                body = b"DEMO_TOKEN=not-a-secret\n"
            elif status == 404:
                body = b"Not found\n"
            else:
                body = b"Local training app\n"
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            if self.path == "/login":
                cookie = "session=training-value; Path=/"
                if hardened:
                    cookie += "; Secure; HttpOnly; SameSite=Lax"
                self.send_header("Set-Cookie", cookie)
            if not hardened:
                self.send_header("X-App-Build", "demo-1.0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def assess(url):
    # Disable proxy inheritance so localhost data stays local.
    opener = build_opener(ProxyHandler({}))
    observations = []
    for path in ("/debug", "/login", "/"):
        try:
            response = opener.open(url + path, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            observations.append(dict(path=path, status=response.code,
                                     headers=dict(response.headers),
                                     body=response.read(4096).decode("utf-8")))
    debug, login, home = observations
    cookie = login["headers"].get("Set-Cookie", "")
    checks = {
        "debug_endpoint_removed": debug["status"] == 404,
        "cookie_secure": "; secure" in cookie.lower(),
        "cookie_httponly": "; httponly" in cookie.lower(),
        "build_header_removed": "X-App-Build" not in home["headers"],
    }
    # Strip nondeterministic HTTP Date headers from stored evidence.
    for row in observations:
        row["headers"].pop("Date", None)
    return dict(checks=checks, observations=observations)


def exercise():
    output = {"scope": "Temporary loopback HTTP training app; no real secrets or production assessment"}
    for mode in ("vulnerable", "hardened"):
        with demo_server(hardened=mode == "hardened") as url:
            output[mode] = assess(url)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("reports/local_web"))
    args = parser.parse_args()
    evidence = exercise()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "before_after.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("Loopback HTTP exercise complete. Hardened mode checks:", evidence["hardened"]["checks"])
    print("Evidence:", args.out / "before_after.json")


if __name__ == "__main__":
    main()
