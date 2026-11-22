"""
VeilCred Studio: a zero-dependency web UI for the whole project.

    python server.py            (then open http://localhost:8000)
    python server.py 8080       (different port)

The server plays all roles in one process: issuer (university), holder (wallet) and verifier.
Every proof shown in the UI is produced and checked by the real VeilCred code.
"""
import json
import secrets
import sys
import threading
import time
import webbrowser
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from veilcred.attacks import ATTACKS, REV, Lab, Credential, _fingerprint
from veilcred.bbs import encode_attribute, present, sign, verify_presentation
from veilcred.pairing import BACKEND
from veilcred.revocation import new_handle

WEB = Path(__file__).parent / "web"
FIELDS = ["name", "dob", "degree", "cgpa"]
IDX = {"name": 0, "dob": 1, "degree": 2, "cgpa": 3}
LOCK = threading.Lock()
W = {}                                          # the one in-memory "world"


def age18_cutoff() -> int:
    t = date.today()
    try:
        d = date(t.year - 18, t.month, t.day)
    except ValueError:                          # 29 Feb
        d = date(t.year - 18, 2, 28)
    return d.year * 10000 + d.month * 100 + d.day


def fmt_dob(n: int) -> str:
    s = str(n)
    return f"{s[:4]}-{s[4:6]}-{s[6:]}"


def issue(name: str, dob: int, degree: str, cgpa10: int) -> dict:
    lab = W["lab"]
    handle = new_handle()
    msgs = [encode_attribute(name), dob, encode_attribute(degree), cgpa10, handle]
    cred = Credential(msgs, sign(lab.params, lab.sk, msgs), handle)
    W["next_id"] += 1
    entry = {"id": W["next_id"], "raw": {"name": name, "dob": dob, "degree": degree, "cgpa": cgpa10},
             "cred": cred}
    W["wallet"].append(entry)
    return entry


def reset():
    W["lab"] = Lab()
    W["wallet"], W["next_id"] = [], 0
    issue("Alice Rao", 20030417, "BTech CSE", 91)
    issue("Bob Nair", 20100101, "BTech CSE", 87)        # a minor
    issue("Carol Iyer", 20010202, "MTech AI", 64)       # adult, low CGPA


def find(cid) -> dict:
    for e in W["wallet"]:
        if e["id"] == int(cid):
            return e
    raise ValueError("unknown credential")


def view(e) -> dict:
    r = e["raw"]
    return {"id": e["id"], "name": r["name"], "dob": fmt_dob(r["dob"]), "degree": r["degree"],
            "cgpa": r["cgpa"] / 10, "revoked": e["cred"].handle in W["lab"].registry.snapshot()}


# ------------------------------------------------------------------ API
def api_state(_=None):
    lab = W["lab"]
    return {"backend": BACKEND, "issuer_pk": lab.pk.encode().hex()[:40],
            "epoch": lab.registry.epoch, "blacklist": len(lab.registry.snapshot()),
            "creds": [view(e) for e in W["wallet"]], "age_cutoff": fmt_dob(age18_cutoff()),
            "attacks": [{"id": i, "category": c, "name": n} for i, (c, n, _) in enumerate(ATTACKS)]}


def api_issue(b):
    name, degree = str(b["name"]).strip()[:40], str(b["degree"]).strip()[:40]
    dob = int(date.fromisoformat(b["dob"]).strftime("%Y%m%d"))
    cgpa = float(b["cgpa"])
    if not name or not degree or not (0 <= cgpa <= 10) or not (19000101 <= dob <= 20991231):
        raise ValueError("please fill in valid details")
    issue(name, dob, degree, int(round(cgpa * 10)))
    return api_state()


def api_revoke(b):
    W["lab"].registry.revoke(find(b["cred_id"])["cred"].handle)
    return api_state()


def api_reset(_):
    reset()
    return api_state()


def api_present(b):
    lab, e = W["lab"], find(b["cred_id"])
    raw, cred = e["raw"], e["cred"]
    reveal = {IDX[f] for f in b.get("reveal", []) if f in IDX}
    preds, texts = [], {}
    if b.get("age18"):
        preds.append((1, "le", age18_cutoff()))
        texts[1] = f"age \u2265 18 (born on/before {fmt_dob(age18_cutoff())})"
    if b.get("cgpa_min") is not None:
        m = float(b["cgpa_min"])
        preds.append((3, "ge", int(round(m * 10))))
        texts[3] = f"CGPA \u2265 {m:.1f}"
    check_rev = bool(b.get("check_revocation", True))
    blacklist = lab.registry.snapshot()
    revocation = (REV, blacklist) if check_rev else None
    nonce = secrets.token_bytes(16)

    out = {"holder": view(e), "nonce": nonce.hex(), "predicates": [texts[p[0]] for p in preds],
           "blacklist": len(blacklist), "check_revocation": check_rev}
    t0 = time.time()
    try:
        pres = present(lab.params, lab.pk, cred.sig, cred.msgs, reveal, nonce,
                       predicates=preds, revocation=revocation)
    except ValueError as err:
        msg = str(err)
        if msg.startswith("predicate not satisfied"):
            msg = "the credential does not satisfy the requested condition, so no valid proof exists"
        elif "revoked" in msg:
            msg = "this credential is revoked, so a proof of non-revocation cannot be built"
        elif "HIDDEN" in msg:
            msg = "an attribute cannot be both revealed and used in a predicate; untick it under 'reveal'"
        out.update(ok=False, stage="holder", message=msg)
        return out
    t1 = time.time()
    ok = verify_presentation(lab.params, lab.pk, pres, nonce, require=preds, revocation=revocation)
    t2 = time.time()

    rows = []
    for f in FIELDS:
        i = IDX[f]
        if i in reveal:
            v = fmt_dob(raw["dob"]) if f == "dob" else (raw["cgpa"] / 10 if f == "cgpa" else raw[f])
            rows.append({"field": f, "state": "revealed", "value": v})
        elif i in texts:
            rows.append({"field": f, "state": "proven", "text": texts[i]})
        else:
            rows.append({"field": f, "state": "hidden"})
    rows.append({"field": "revocation handle", "state": "proven" if check_rev else "hidden",
                 "text": f"not on the blacklist ({len(blacklist)} entries checked)"})
    fp = _fingerprint(pres)
    out.update(ok=ok, stage="verifier",
               message="Verifier accepts the presentation" if ok else "Verifier rejects the presentation",
               rows=rows,
               inspector={"A_prime": pres.A_prime.encode().hex()[:48], "A_bar": pres.A_bar.encode().hex()[:48],
                          "d": pres.d.encode().hex()[:48], "elements": len(fp),
                          "bytes": sum(len(x) for x in fp), "prove_ms": round((t1 - t0) * 1000),
                          "verify_ms": round((t2 - t1) * 1000),
                          "range_bits": sum(len(p.proof.Cs) for p in pres.predicate_proofs)})
    return out


def api_attack(b):
    category, name, fn = ATTACKS[int(b["id"])]
    t = time.time()
    try:
        passed, note = fn(Lab())
    except Exception as err:                    # a crash is a failure, not a defence
        passed, note = False, f"unexpected exception: {type(err).__name__}: {err}"
    return {"id": int(b["id"]), "passed": bool(passed), "note": note,
            "seconds": round(time.time() - t, 2), "control": category == "control"}


def api_unlink(b):
    lab, e = W["lab"], find(b["cred_id"])
    n = max(2, min(int(b.get("n", 6)), 10))
    bl = lab.registry.snapshot()
    runs = []
    for _ in range(n):
        p = present(lab.params, lab.pk, e["cred"].sig, e["cred"].msgs, {2}, secrets.token_bytes(16),
                    revocation=(REV, bl))
        runs.append(p.A_prime.encode().hex())
    naive = e["cred"].sig.A.encode().hex()
    return {"veilcred": runs, "naive": [naive] * n, "distinct": len(set(runs))}


def api_bench(_):
    lab = W["lab"]
    rows = []
    for n in (0, 4, 8, 16):
        cred = Credential([encode_attribute("Bench"), 20030417, encode_attribute("BTech"), 91, new_handle()], None, 0)
        cred.sig = sign(lab.params, lab.sk, cred.msgs)
        bl = [new_handle() for _ in range(n)]
        pred = [(1, "le", age18_cutoff())]
        t0 = time.time()
        p = present(lab.params, lab.pk, cred.sig, cred.msgs, {2}, b"bench", predicates=pred, revocation=(REV, bl))
        t1 = time.time()
        ok = verify_presentation(lab.params, lab.pk, p, b"bench", require=pred, revocation=(REV, bl))
        t2 = time.time()
        rows.append({"blacklist": n, "prove_ms": round((t1 - t0) * 1000), "verify_ms": round((t2 - t1) * 1000), "ok": ok})
    return {"rows": rows}


ROUTES = {("GET", "/api/state"): api_state, ("POST", "/api/issue"): api_issue,
          ("POST", "/api/revoke"): api_revoke, ("POST", "/api/reset"): api_reset,
          ("POST", "/api/present"): api_present, ("POST", "/api/attack"): api_attack,
          ("POST", "/api/unlink"): api_unlink, ("POST", "/api/bench"): api_bench}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method):
        path = self.path.split("?")[0]
        if method == "GET" and path in ("/", "/index.html"):
            return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
        fn = ROUTES.get((method, path))
        if fn is None:
            return self._send(404, b'{"error": "not found"}')
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}") if method == "POST" else None
            with LOCK:                          # one crypto job at a time
                result = fn(body)
            self._send(200, json.dumps(result).encode())
        except Exception as err:
            self._send(400, json.dumps({"error": f"{type(err).__name__}: {err}"}).encode())

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def log_message(self, *args):               # keep the console quiet
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    reset()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://localhost:{port}"
    print(f"VeilCred Studio running on {url}   [backend: {BACKEND}]   (Ctrl+C to stop)")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()