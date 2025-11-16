#!/usr/bin/env python3
"""
openapi_runner.py

Usage examples:
  # quick: provide token on CLI (recommended)
  python openapi_runner.py --config-url "https://dev-api.taxbuddy.com/itr/swagger/config" --token "eyJ..."

  # or provide token via environment variable:
  set TOKEN=eyJ...
  python openapi_runner.py --config-url "https://dev-api.taxbuddy.com/itr/swagger/config"

  # optionally pass path-values.json mapping to fill path params:
  python openapi_runner.py --config-url ... --token ... --path-values path_values.json

Notes:
 - This will perform real API calls. Use staging/test environment or ensure you have permission.
 - For POST/PUT/PATCH it will auto-generate a sample JSON body from the requestBody schema.
"""

import argparse, json, os, re, time, csv, html
from urllib.parse import urljoin
import requests

# ---------- Helpers ----------
_param_re = re.compile(r"\{([^}]+)\}")

def safe_get(url, headers=None, timeout=20):
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout)
        return r
    except Exception as e:
        print("GET error:", e)
        return None

def safe_request(method, url, headers=None, json_body=None, timeout=30):
    try:
        r = requests.request(method, url, headers=headers or {}, json=json_body, timeout=timeout)
        return r
    except Exception as e:
        return e

# ---------- Schema sample generator ----------
def resolve_ref(ref, components):
    # ref like "#/components/schemas/MyModel"
    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node = components
    for p in parts[1:]:  # skip initial "components"
        node = node.get(p, {})
    return node

def sample_from_schema(schema, components):
    if not schema:
        return None
    # handle $ref
    if "$ref" in schema:
        ref_schema = resolve_ref(schema["$ref"], {"components": components})
        return sample_from_schema(ref_schema, components)
    t = schema.get("type")
    if "enum" in schema:
        return schema["enum"][0]
    if t == "string" or (t is None and "properties" not in schema):
        fmt = schema.get("format","")
        if fmt in ("email",):
            return "test@example.com"
        if fmt in ("uuid",):
            return "11111111-1111-1111-1111-111111111111"
        if fmt in ("date-time","date"):
            return "2023-01-01T00:00:00Z"
        # example or default
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        return "string_sample"
    if t == "integer" or t == "number":
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        return 1
    if t == "boolean":
        return schema.get("example", True)
    if t == "array":
        items = schema.get("items", {})
        return [ sample_from_schema(items, components) ]
    if t == "object" or "properties" in schema:
        obj = {}
        props = schema.get("properties", {})
        for k,v in props.items():
            obj[k] = sample_from_schema(v, components)
        # additionalProperties case
        if not props and schema.get("additionalProperties"):
            obj["key1"] = sample_from_schema(schema["additionalProperties"], components)
        return obj
    # fallback
    return None

# ---------- OpenAPI helpers ----------
def extract_base_from_openapi(openapi):
    # prefer servers[0].url
    if "servers" in openapi and openapi["servers"]:
        return openapi["servers"][0].get("url","").rstrip("/")
    # fallback: components host/basePath? (rare)
    host = openapi.get("host","")
    basePath = openapi.get("basePath","")
    schemes = openapi.get("schemes", ["https"])
    if host:
        scheme = schemes[0] if schemes else "https"
        return f"{scheme}://{host}{basePath}".rstrip("/")
    return ""

def extract_endpoints(openapi):
    paths = openapi.get("paths", {})
    endpoints = []
    for path, methods in paths.items():
        for method, meta in methods.items():
            if method.lower() not in ("get","post","put","patch","delete","head","options"):
                continue
            endpoints.append({
                "path": path,
                "method": method.upper(),
                "operationId": meta.get("operationId") or "",
                "parameters": meta.get("parameters", []),
                "requestBody": meta.get("requestBody"),
                "responses": meta.get("responses", {}),
            })
    return endpoints

def instantiate_url(template, path_values=None):
    if path_values is None:
        path_values = {}
    def repl(m):
        k = m.group(1)
        if k in path_values:
            return str(path_values[k])
        # some common param names -> sample
        common = {"id":"1","agent_id":"1","userId":"1","user_id":"1","tenantId":"1","subscription_id":"1"}
        if k in common:
            return common[k]
        # if param name contains uuid
        if "uuid" in k.lower() or "id" in k.lower():
            return "11111111-1111-1111-1111-111111111111"
        return "1"
    return _param_re.sub(repl, template)

# ---------- main testing flow ----------
def run(openapi, token, path_values=None, do_fuzz=False, do_rate=False):
    components = openapi.get("components", {}).get("schemas", {})
    base = extract_base_from_openapi(openapi)
    if not base:
        raise SystemExit("Cannot determine base URL from OpenAPI spec")
    print("Base URL:", base)

    endpoints = extract_endpoints(openapi)
    print("Total endpoints found:", len(endpoints))

    results = []
    headers = {"Accept":"application/json"}
    if token:
        # token may already include "Bearer". ensure correct header form
        h = token.strip()
        if not h.lower().startswith("bearer "):
            h = "Bearer " + h
        headers["Authorization"] = h

    for ep in endpoints:
        url_template = base + ep["path"]
        url = instantiate_url(url_template, path_values)
        method = ep["method"]
        print(f"[{method}] {url}")

        body = None
        # build body for methods that accept a requestBody
        if method in ("POST","PUT","PATCH") and ep.get("requestBody"):
            # OpenAPI v3: requestBody -> content -> application/json -> schema
            rb = ep["requestBody"]
            content = rb.get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema")
                body = sample_from_schema(schema, components)
            else:
                # pick first available content type
                for ct, info in content.items():
                    schema = info.get("schema")
                    if schema:
                        body = sample_from_schema(schema, components)
                        break

        # make the call
        try:
            resp = safe_request(method, url, headers=headers, json_body=body)
            if isinstance(resp, Exception):
                status = "ERROR"
                text = str(resp)
            else:
                status = resp.status_code
                text = resp.text[:1000]
        except Exception as e:
            status = "ERROR"
            text = str(e)

        # record
        rec = {
            "operationId": ep.get("operationId"),
            "method": method,
            "url": url,
            "status": status,
            "body_sample": json.dumps(body) if body is not None else "",
            "response_preview": text
        }
        results.append(rec)

        # small sleep to avoid bursting (adjust if needed)
        time.sleep(0.05)

    return results

# ---------- reporting ----------
def write_csv(results, out="results/api_results.csv"):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["operationId","method","url","status","body_sample","response_preview"])
        for r in results:
            w.writerow([r["operationId"], r["method"], r["url"], r["status"], r["body_sample"], r["response_preview"]])
    print("CSV written to", out)

def write_html(results, out="results/api_report.html"):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as hf:
        hf.write("<html><head><meta charset='utf-8'><title>API Report</title></head><body>")
        hf.write("<h1>API Run Report</h1>")
        hf.write(f"<p>Generated: {time.ctime()}</p>")
        hf.write("<table border='1' cellpadding='6' style='border-collapse:collapse'>")
        hf.write("<tr><th>Operation</th><th>Method</th><th>URL</th><th>Status</th><th>Body sample</th><th>Response preview</th></tr>")
        for r in results:
            hf.write("<tr>")
            hf.write(f"<td>{html.escape(str(r.get('operationId') or ''))}</td>")
            hf.write(f"<td>{html.escape(r.get('method'))}</td>")
            hf.write(f"<td><a href='{html.escape(r.get('url'))}' target='_blank'>{html.escape(r.get('url'))}</a></td>")
            hf.write(f"<td>{html.escape(str(r.get('status')))}</td>")
            hf.write(f"<td><pre>{html.escape(str(r.get('body_sample')))}</pre></td>")
            hf.write(f"<td><pre>{html.escape(str(r.get('response_preview')))}</pre></td>")
            hf.write("</tr>")
        hf.write("</table></body></html>")
    print("HTML written to", out)

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config-url", help="Swagger config URL (swagger UI config) e.g. https://dev-api.taxbuddy.com/itr/swagger/config", required=False)
    p.add_argument("--openapi-url", help="Direct openapi url e.g. https://dev-api.taxbuddy.com/itr/v3/api-docs", required=False)
    p.add_argument("--token", help="Bearer token (paste token string) or set env var TOKEN", required=False)
    p.add_argument("--path-values", help="Optional JSON file mapping path param names to values", required=False)
    args = p.parse_args()

    token = args.token or os.environ.get("TOKEN")
    if not token:
        print("No token provided. Use --token or set TOKEN environment variable.")
        return

    # discover openapi url
    openapi_url = args.openapi_url
    if not openapi_url:
        if not args.config_url:
            print("Provide --config-url or --openapi-url")
            return
        # fetch config and read 'url' field
        cfg = safe_get(args.config_url, headers={"Authorization":("Bearer " + token)})
        if not cfg:
            print("Unable to fetch config URL")
            return
        try:
            cfgj = cfg.json()
            openapi_url = cfgj.get("url")
            if not openapi_url:
                print("config JSON did not contain 'url' key; please provide --openapi-url directly")
                return
        except Exception as e:
            print("Error parsing config JSON:", e)
            return

    print("Using OpenAPI URL:", openapi_url)
    # fetch openapi
    r = safe_get(openapi_url, headers={"Authorization": ("Bearer " + token)})
    if not r or r.status_code != 200:
        print("Unable to fetch OpenAPI JSON. Status:", None if not r else r.status_code)
        return
    openapi = r.json()

    # load optional path values
    path_values = {}
    if args.path_values:
        try:
            path_values = json.load(open(args.path_values))
        except Exception as e:
            print("Cannot read path values file:", e)

    results = run(openapi, token, path_values=path_values)
    write_csv(results)
    write_html(results)
    print("Completed. Reports in ./results/")

if __name__ == "__main__":
    main()
