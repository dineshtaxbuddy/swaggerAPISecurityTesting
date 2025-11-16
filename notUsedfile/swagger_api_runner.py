#!/usr/bin/env python3
"""
swagger_api_runner.py

Purpose:
 - Use a Bearer token (or optionally login) to fetch the swagger/openapi spec
 - Enumerate endpoints and call them one-by-one
 - Do basic security checks: missing-auth behavior, simple fuzzing, 5xx/429 detection
 - Produce CSV and HTML reports in output/results/

Usage examples:
  1) If you already have a bearer token (fast):
     python swagger_api_runner.py --config-url "https://dev-api.taxbuddy.com/itr/swagger/config" --token "eyJ..."

  2) If you want to provide swagger URL directly:
     python swagger_api_runner.py --swagger-url "https://dev-api.taxbuddy.com/itr/swagger/v1/swagger.json" --token "eyJ..."

Notes:
 - For login automation (posting username/password/service) the script provides a --login-url option,
   but you must supply JSON payload keys with --login-payload '{"username":"...","password":"...","service":"ITR"}'
 - Avoid running fuzzing or rate tests against production without permission.
"""

import argparse, json, os, re, time, csv, html
from urllib.parse import urljoin
import requests
from tqdm import tqdm

OUTPUT_DIR = "output"
RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

TIMEOUT = 15
FUZZ_PAYLOADS = ["' OR '1'='1", "<script>alert(1)</script>", "../../etc/passwd", "😊"]
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{8,})"),
    re.compile(r"(?i)secret\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{8,})"),
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),  # naive CC pattern
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
]

# -------- helpers --------
def safe_get(url, headers=None):
    try:
        r = requests.get(url, headers=headers or {}, timeout=TIMEOUT)
        return r
    except Exception as e:
        print("GET error:", e)
        return None

def safe_post(url, headers=None, json_body=None):
    try:
        r = requests.post(url, headers=headers or {}, json=json_body, timeout=TIMEOUT)
        return r
    except Exception as e:
        print("POST error:", e)
        return None

def fetch_config(config_url, headers):
    r = safe_get(config_url, headers=headers)
    if not r:
        return None
    try:
        return r.json()
    except Exception:
        return None

def discover_swagger_url_from_config(cfg_json):
    # Try common fields
    if not cfg_json:
        return None
    # Many apps return the swagger URL under keys like swaggerUrl, url, openApiUrl, specUrl or similar
    for key in ("swaggerUrl","swagger_url","swagger","openapi","openapi_url","spec","specUrl","config","url"):
        if key in cfg_json and isinstance(cfg_json[key], str):
            return cfg_json[key]
    # scan values for .json or /swagger
    for v in cfg_json.values():
        if isinstance(v, str) and (".json" in v or "/swagger" in v):
            return v
    return None

def load_swagger(swagger_url, headers):
    print("Fetching swagger/openapi from:", swagger_url)
    r = safe_get(swagger_url, headers=headers)
    if not r:
        raise RuntimeError("Cannot fetch swagger: " + str(swagger_url))
    try:
        return r.json()
    except Exception:
        # maybe YAML text
        text = r.text
        import yaml
        return yaml.safe_load(text)

def extract_endpoints_from_spec(spec, base_override=None):
    # support Swagger 2.0 and OpenAPI 3.x
    base = ""
    if base_override:
        base = base_override.rstrip("/")
    else:
        # swagger 2.0: host + basePath + schemes
        if spec.get("swagger") == "2.0":
            host = spec.get("host","")
            basePath = spec.get("basePath","")
            schemes = spec.get("schemes", [])
            scheme = schemes[0] if schemes else "https"
            if host:
                base = f"{scheme}://{host}{basePath}"
        # openapi 3: servers[]
        if not base and spec.get("openapi"):
            servers = spec.get("servers", [])
            if servers:
                base = servers[0].get("url","")
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, meta in methods.items():
            if method.lower() not in ("get","post","put","patch","delete","head","options"):
                continue
            url_template = (base.rstrip("/") + "/" + path.lstrip("/")).replace("//","/")
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "operationId": meta.get("operationId") or meta.get("operationId",""),
                "summary": meta.get("summary",""),
                "parameters": meta.get("parameters", []),
                "requestBody": meta.get("requestBody"),
                "url_template": url_template,
            })
    return endpoints

_param_re = re.compile(r"\{([^}]+)\}")
def instantiate_url(template, path_values=None):
    if path_values is None:
        path_values = {}
    def repl(m):
        k = m.group(1)
        # pick a provided value else try common names else fallback '1'
        if k in path_values:
            return str(path_values[k])
        common = {"id":"1","agent_id":"1","userId":"1","user_id":"1","tenantId":"1"}
        if k in common:
            return common[k]
        return "1"
    return _param_re.sub(repl, template)

def find_sensitive(text):
    found = set()
    for p in SENSITIVE_PATTERNS:
        for m in p.findall(text or ""):
            if isinstance(m, tuple):
                m = m[0]
            found.add(str(m))
    return list(found)

def call_endpoint(method, url, headers=None, json_body=None):
    try:
        r = requests.request(method, url, headers=headers or {}, json=json_body, timeout=TIMEOUT)
        return {"status": r.status_code, "headers": dict(r.headers), "text": r.text}
    except Exception as e:
        return {"status": "error", "error": str(e), "text": ""}

# -------- tests per endpoint --------
def test_endpoint(ep, headers, do_fuzz=True, do_rate=False, path_values=None):
    res = {
        "operationId": ep.get("operationId") or ep.get("path"),
        "method": ep["method"],
        "url_template": ep["url_template"],
        "url": None,
        "baseline_status": None,
        "baseline_latency_ms": None,
        "missing_auth_status": None,
        "auth_tamper_status": None,
        "fuzz_issues": [],
        "sensitive": [],
        "rate_test": {},
        "errors": [],
    }
    url = instantiate_url(ep["url_template"], path_values or {})
    res["url"] = url

    # baseline call (with current headers)
    t0 = time.time()
    base_resp = call_endpoint(ep["method"], url, headers=headers)
    t1 = time.time()
    res["baseline_latency_ms"] = int((t1 - t0) * 1000)
    res["baseline_status"] = base_resp.get("status")
    if base_resp.get("text"):
        res["sensitive"] = find_sensitive(base_resp.get("text"))

    # check missing auth (if Authorization present in headers)
    if headers and "Authorization" in headers:
        h2 = dict(headers)
        h2.pop("Authorization", None)
        missing = call_endpoint(ep["method"], url, headers=h2)
        res["missing_auth_status"] = missing.get("status")
        # tampered token
        tam = dict(headers)
        tam["Authorization"] = tam.get("Authorization","") + "X"
        tam_resp = call_endpoint(ep["method"], url, headers=tam)
        res["auth_tamper_status"] = tam_resp.get("status")
        # If baseline ok and missing auth ok -> possible misconfig
        try:
            b = int(res["baseline_status"])
            m = int(res["missing_auth_status"])
            if b < 300 and m < 300:
                res["errors"].append("Endpoint responds successfully without auth; check if it should be protected.")
        except Exception:
            pass

    # basic fuzzing
    if do_fuzz:
        fuzz_findings = []
        method = ep["method"].upper()
        if method == "GET":
            for p in FUZZ_PAYLOADS[:3]:
                sep = "&" if "?" in url else "?"
                fuzz_url = url + sep + "q=" + requests.utils.quote(p)
                r = call_endpoint("GET", fuzz_url, headers=headers)
                status = r.get("status")
                if isinstance(status, int) and status >= 500:
                    fuzz_findings.append({"type":"server_error","payload":p,"status":status})
                if p in (r.get("text") or ""):
                    fuzz_findings.append({"type":"reflected","payload":p})
        else:
            for p in FUZZ_PAYLOADS[:2]:
                body = {"test": p}
                r = call_endpoint(method, url, headers=headers, json_body=body)
                status = r.get("status")
                if isinstance(status, int) and status >= 500:
                    fuzz_findings.append({"type":"server_error","payload":p,"status":status})
                if p in (r.get("text") or ""):
                    fuzz_findings.append({"type":"reflected","payload":p})
        res["fuzz_issues"] = fuzz_findings
        if fuzz_findings:
            res["errors"].append("Fuzz findings: %d" % len(fuzz_findings))

    # simple rate test (optional)
    if do_rate:
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def one_call():
                r = call_endpoint(ep["method"], url, headers=headers)
                return r.get("status")
            burst = 20
            concurrency = 8
            statuses = []
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                futures = [ex.submit(one_call) for _ in range(burst)]
                for f in as_completed(futures):
                    statuses.append(f.result())
            counts = {}
            for s in statuses:
                counts[s] = counts.get(s,0) + 1
            res["rate_test"] = {"total": len(statuses), "counts": counts}
            if any((isinstance(k,int) and (k==429 or (k>=500 and k<600))) for k in counts):
                res["errors"].append("Rate test observed 429/5xx responses or instability")
        except Exception as e:
            res["rate_test"] = {"error": str(e)}
    return res

# -------- reporting --------
def write_csv(results, out_file):
    with open(out_file, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["operationId","method","url","baseline_status","latency_ms","missing_auth_status","auth_tamper_status","fuzz_issues_count","sensitive","rate_total","rate_counts","errors"])
        for r in results:
            w.writerow([
                r.get("operationId"),
                r.get("method"),
                r.get("url"),
                r.get("baseline_status"),
                r.get("baseline_latency_ms"),
                r.get("missing_auth_status"),
                r.get("auth_tamper_status"),
                len(r.get("fuzz_issues") or []),
                ",".join(r.get("sensitive") or []),
                r.get("rate_test",{}).get("total",""),
                json.dumps(r.get("rate_test",{}).get("counts","")),
                ";".join(r.get("errors") or [])
            ])
    print("CSV written to", out_file)

def write_html(results, out_file):
    with open(out_file, "w", encoding="utf-8") as hf:
        hf.write("<html><head><meta charset='utf-8'><title>API Run Report</title></head><body>")
        hf.write("<h1>API Run Report</h1>")
        hf.write(f"<p>Generated: {time.ctime()}</p>")
        hf.write("<table border='1' cellpadding='6' style='border-collapse:collapse'>")
        hf.write("<tr><th>Operation</th><th>Method</th><th>URL</th><th>Status</th><th>Latency ms</th><th>Fuzz</th><th>Sensitive</th><th>Rate</th><th>Errors</th></tr>")
        for r in results:
            hf.write("<tr>")
            hf.write("<td>%s</td>" % html.escape(str(r.get("operationId"))))
            hf.write("<td>%s</td>" % html.escape(str(r.get("method"))))
            hf.write("<td><a href='%s' target='_blank'>%s</a></td>" % (html.escape(r.get("url")), html.escape(r.get("url"))))
            hf.write("<td>%s</td>" % html.escape(str(r.get("baseline_status"))))
            hf.write("<td>%s</td>" % html.escape(str(r.get("baseline_latency_ms"))))
            hf.write("<td>%s</td>" % html.escape(str(len(r.get("fuzz_issues") or []))))
            hf.write("<td>%s</td>" % html.escape(",".join(r.get("sensitive") or [])))
            hf.write("<td>%s</td>" % html.escape(json.dumps(r.get("rate_test") or {})))
            hf.write("<td>%s</td>" % html.escape(";".join(r.get("errors") or [])))
            hf.write("</tr>")
        hf.write("</table></body></html>")
    print("HTML written to", out_file)

# -------- main CLI --------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config-url", help="URL to the app config (like /itr/swagger/config) - optional")
    p.add_argument("--swagger-url", help="Direct URL to swagger/openapi JSON (skip config discovery)")
    p.add_argument("--token", help="Bearer token (if you already have it). If provided the script will use it.")
    p.add_argument("--login-url", help="Optional login API URL (if you want script to obtain token) - expects JSON payload from --login-payload")
    p.add_argument("--login-payload", help="JSON string payload for login, e.g. '{\"username\":\"...\",\"password\":\"...\",\"service\":\"ITR\"}'")
    p.add_argument("--do-fuzz", action="store_true", help="Enable simple fuzzing")
    p.add_argument("--do-rate", action="store_true", help="Enable simple rate testing (slower)")
    p.add_argument("--path-values", help="Optional JSON file with path param values mapping")
    p.add_argument("--output-dir", default=OUTPUT_DIR, help="Output directory")
    args = p.parse_args()

    outdir = args.output_dir
    results_dir = os.path.join(outdir, "results")
    os.makedirs(results_dir, exist_ok=True)

    headers = {"Accept": "application/json"}
    token = None

    # If token provided, use it
    if args.token:
        token = args.token
    # If login details provided, try to get token
    elif args.login_url and args.login_payload:
        try:
            payload = json.loads(args.login_payload)
        except Exception as e:
            print("Invalid login payload JSON:", e)
            return
        r = safe_post(args.login_url, json_body=payload, headers={"Accept":"application/json"})
        if not r:
            print("Login failed")
            return
        try:
            jr = r.json()
            # heuristics: find token in common places
            for k in ("token","access_token","id_token","jwt"):
                if k in jr:
                    token = jr[k]
                    break
            if not token:
                # maybe nested
                def find_token_in_obj(o):
                    if isinstance(o, dict):
                        for kk,v in o.items():
                            if kk.lower() in ("token","access_token","id_token","jwt"):
                                return v
                            res = find_token_in_obj(v)
                            if res:
                                return res
                    return None
                token = find_token_in_obj(jr)
        except Exception:
            print("Login response not JSON; cannot find token")
            return
    # attach token to headers if found
    if token:
        headers["Authorization"] = "Bearer " + token
        # do not print token in logs
        print("Using bearer token (length %d) in Authorization header." % len(token))

    # 1) Discover swagger/openapi
    spec = None
    swagger_url = args.swagger_url
    if not swagger_url and args.config_url:
        cfg_json = fetch_config(args.config_url, headers)
        discovered = discover_swagger_url_from_config(cfg_json)
        if discovered:
            # if discovered is relative, join with config base
            if discovered.startswith("/"):
                base = args.config_url.split("/",3)[:3]  # crude
                swagger_url = urljoin(args.config_url, discovered)
            else:
                swagger_url = discovered
        else:
            # try common fallback paths relative to config service root
            # e.g. /itr/swagger/v1/swagger.json or /v2/api-docs etc.
            base_candidate = args.config_url.rsplit("/",1)[0]
            candidates = [
                base_candidate + "/v1/swagger.json",
                base_candidate + "/swagger.json",
                base_candidate + "/v2/api-docs",
                base_candidate + "/openapi.json",
                base_candidate + "/openapi",
            ]
            for c in candidates:
                rr = safe_get(c, headers=headers)
                if rr and rr.status_code == 200:
                    swagger_url = c
                    break

    if not swagger_url:
        print("No swagger URL discovered. Provide --swagger-url or a config URL that returns swaggerUrl.")
        return

    try:
        spec = load_swagger(swagger_url, headers)
    except Exception as e:
        print("Failed to fetch/parse swagger:", e)
        return

    # 2) Extract endpoints
    endpoints = extract_endpoints_from_spec(spec)
    print("Discovered %d endpoints from swagger." % len(endpoints))
    if len(endpoints) == 0:
        print("No endpoints found in spec; aborting.")
        return

    # optional path values
    path_values = {}
    if args.path_values:
        try:
            path_values = json.load(open(args.path_values))
        except Exception as e:
            print("Cannot load path values:", e)

    results = []
    # call endpoints one by one
    for ep in tqdm(endpoints, desc="Running endpoints"):
        try:
            r = test_endpoint(ep, headers=headers, do_fuzz=args.do_fuzz, do_rate=args.do_rate, path_values=path_values)
            results.append(r)
        except Exception as e:
            print("Error testing endpoint", ep.get("path"), e)

    # write reports
    csv_file = os.path.join(results_dir, "results.csv")
    html_file = os.path.join(results_dir, "report.html")
    write_csv(results, csv_file)
    write_html(results, html_file)
    print("All done. Reports at:", results_dir)

if __name__ == "__main__":
    main()
