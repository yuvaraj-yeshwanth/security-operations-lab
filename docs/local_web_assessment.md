# Executed local HTTP assessment

Run:

```bash
python src/web_lab.py --out reports/local_web
```

The script runs two sequential, temporary HTTP servers on `127.0.0.1` with operating-system-assigned ports. It uses no third-party targets, passwords or real secrets. It requests `/debug`, `/login`, and `/`, then stores observed status codes, headers and bodies. Each server stops automatically.

| Check | Vulnerable mode | Hardened mode |
| --- | --- | --- |
| Debug route | 200; body contains `DEMO_TOKEN=not-a-secret` | 404; marker absent |
| Session cookie | Lacks Secure and HttpOnly | Includes Secure, HttpOnly and SameSite=Lax |
| Build header | `X-App-Build: demo-1.0` | Header absent |

The four automated booleans check debug removal, Secure, HttpOnly and build-header removal. SameSite is visible in the recorded header; there is no automated SameSite assertion. The test also verifies the marker disappears.

The application is deliberately minimal: no real login, session validation, database, authorization model or TLS. Adding cookie flags alone does not make this application secure. `Secure` cookies are intended for HTTPS; this HTTP loopback exercise only inspects the header, not browser cookie behavior. Python's standard HTTP server is a training convenience, not a deployment recommendation.

The synthetic vulnerability fixture mirrors these teaching examples, but its labels and exposure flags are fictional. The actual exercised application is loopback-only and is not internet exposed.

## Evidence review

Read `examples/local_web/before_after.json`, then generate your own output. Identify the HTTP status, body and header that support each observation. Explain which conclusions require a real browser, authenticated workflow and TLS-enabled deployment to verify.
