#!/usr/bin/env python3
"""Load a page in headless Chromium and report what actually happened.

Exists because the offline UI is pure frontend and nothing here could run
its JavaScript — the v1.6 settings panel had never been executed anywhere,
and the class of bug that nearly shipped (markup landing after </script>,
so every getElementById returned null) is invisible to static review.

Uses the DevTools Protocol rather than `--dump-dom`: the UI holds an SSE
connection to /events, so the page never reaches "load complete" and a
one-shot dump hangs forever.

  ./pagecheck.py http://localhost:5000
  ./pagecheck.py http://localhost:5000 --eval "document.title" \
                                       --eval "typeof openSettings"
  ./pagecheck.py http://localhost:5000 --click "#btn-settings" \
                                       --eval "document.querySelector('.settings-backdrop').className"

Exit code is 1 if any uncaught exception or console error was seen.
"""
import argparse, json, os, shutil, signal, subprocess, sys, tempfile, time
import urllib.request
import websocket

CHROME = shutil.which("chromium") or shutil.which("chromium-browser")


def launch(port, window="1280,800"):
    prof = tempfile.mkdtemp(prefix="pagecheck-")
    proc = subprocess.Popen(
        [CHROME, "--headless=new", "--no-sandbox", "--disable-gpu",
         "--disable-dev-shm-usage", f"--user-data-dir={prof}",
         f"--window-size={window}", "--hide-scrollbars",
         "--no-first-run", "--disable-background-networking",
         "--disable-sync", "--disable-default-apps",
         f"--remote-debugging-port={port}",
         # websocket-client sends an Origin header; Chromium 111+ rejects
         # the CDP handshake without this. Safe: the port is loopback-only
         # and this browser instance is torn down at exit.
         "--remote-allow-origins=*", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version",
                                   timeout=1).read()
            return proc, prof
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("chromium did not open a debugging port")


def page_ws(port):
    for _ in range(20):
        raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list",
                                     timeout=2).read()
        for t in json.loads(raw):
            if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                return t["webSocketDebuggerUrl"]
        time.sleep(0.5)
    raise RuntimeError("no page target")


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=30)
        self.n = 0
        self.events = []

    def send(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method,
                                 "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                return msg
            self.events.append(msg)

    def drain(self, seconds):
        end = time.time() + seconds
        self.ws.settimeout(0.5)
        while time.time() < end:
            try:
                self.events.append(json.loads(self.ws.recv()))
            except Exception:
                pass
        self.ws.settimeout(30)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--eval", action="append", default=[],
                    help="JS expression to evaluate after load (repeatable)")
    ap.add_argument("--click", action="append", default=[],
                    help="CSS selector to click before evaluating (repeatable)")
    ap.add_argument("--wait", type=float, default=4.0,
                    help="seconds to let the page settle (default 4)")
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--screenshot", help="write a PNG here after evaluating")
    ap.add_argument("--window", default="1280,800", help="WIDTH,HEIGHT")
    # Headless Chromium refuses to size its window below 500px, so --window
    # cannot reach phone widths and every phone layout went untested. Device
    # emulation can: it drives the viewport the page actually sees, and turns
    # on touch so `pointer: coarse` rules apply as they would on a phone.
    ap.add_argument("--mobile", metavar="WIDTH,HEIGHT",
                    help="emulate a phone viewport, e.g. 390,844 (portrait) "
                         "or 844,390 (landscape)")
    args = ap.parse_args()

    if not CHROME:
        sys.exit("chromium not found")

    proc, prof = launch(args.port, args.window)
    failed = False
    try:
        cdp = CDP(page_ws(args.port))
        cdp.send("Runtime.enable")
        cdp.send("Log.enable")
        cdp.send("Page.enable")
        if args.mobile:
            w, h = (int(n) for n in args.mobile.split(","))
            cdp.send("Emulation.setDeviceMetricsOverride", width=w, height=h,
                     deviceScaleFactor=1, mobile=True)
            cdp.send("Emulation.setTouchEmulationEnabled", enabled=True,
                     maxTouchPoints=5)
            print(f"  emulating {w}x{h} with touch")
        cdp.send("Page.navigate", url=args.url)
        cdp.drain(args.wait)

        for sel in args.click:
            r = cdp.send("Runtime.evaluate", returnByValue=True, expression=f"""
                (() => {{ const el = document.querySelector({json.dumps(sel)});
                          if (!el) return "NO SUCH ELEMENT";
                          el.click(); return "clicked"; }})()""")
            val = r.get("result", {}).get("result", {}).get("value")
            print(f"  click {sel:32} -> {val}")
            if val == "NO SUCH ELEMENT":
                failed = True
            cdp.drain(1.0)

        for expr in args.eval:
            # awaitPromise lets an expression be an async IIFE, so a test can
            # trigger a fetch, wait for it, and report what the DOM became.
            r = cdp.send("Runtime.evaluate", returnByValue=True,
                         awaitPromise=True, expression=expr)
            res = r.get("result", {})
            if "exceptionDetails" in res:
                print(f"  eval {expr!r} -> THREW: "
                      f"{res['exceptionDetails'].get('text')}")
                failed = True
            else:
                print(f"  eval {expr!r} -> "
                      f"{res.get('result', {}).get('value')!r}")

        # CDP screenshot rather than --screenshot: a page holding an SSE
        # connection never reaches "load complete", so the CLI flag waits
        # forever and the browser gets killed before writing anything.
        if args.screenshot:
            import base64
            shot = cdp.send("Page.captureScreenshot", format="png")
            data = shot.get("result", {}).get("data")
            if data:
                with open(args.screenshot, "wb") as fh:
                    fh.write(base64.b64decode(data))
                print(f"  screenshot -> {args.screenshot} "
                      f"({os.path.getsize(args.screenshot)} bytes)")
            else:
                print("  screenshot FAILED")
                failed = True

        # Console errors and uncaught exceptions — the whole reason this exists.
        problems = []
        for e in cdp.events:
            m = e.get("method")
            p = e.get("params", {})
            if m == "Runtime.exceptionThrown":
                d = p.get("exceptionDetails", {})
                problems.append(f"UNCAUGHT: {d.get('text')} "
                                f"{d.get('exception', {}).get('description', '')}"
                                .strip())
            elif m == "Log.entryAdded" and p.get("entry", {}).get("level") == "error":
                en = p["entry"]
                problems.append(f"CONSOLE: {en.get('text')} "
                                f"({en.get('url', '')})".strip())
            elif m == "Runtime.consoleAPICalled" and p.get("type") == "error":
                bits = [a.get("value", a.get("description", ""))
                        for a in p.get("args", [])]
                problems.append("CONSOLE: " + " ".join(str(b) for b in bits))

        print()
        if problems:
            failed = True
            print(f"  {len(problems)} problem(s):")
            for pr in dict.fromkeys(problems):
                print(f"    - {pr}")
        else:
            print("  no console errors or uncaught exceptions")
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        shutil.rmtree(prof, ignore_errors=True)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
