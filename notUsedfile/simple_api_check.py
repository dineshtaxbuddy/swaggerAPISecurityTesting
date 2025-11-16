import requests
import yaml
import json
from urllib.parse import urljoin

SWAGGER_URL = "https://petstore.swagger.io/v2/swagger.json"  # <--- change here


def load_openapi(url):
    print(f"Fetching Swagger/OpenAPI spec from: {url}")
    r = requests.get(url, timeout=10)
    r.raise_for_status()

    try:
        return r.json()
    except:
        return yaml.safe_load(r.text)


def extract_base(spec):
    # OpenAPI v3
    if "servers" in spec and spec["servers"]:
        return spec["servers"][0]["url"]
    # Swagger v2
    if "host" in spec:
        scheme = spec.get("schemes", ["https"])[0]
        base_path = spec.get("basePath", "")
        return f"{scheme}://{spec['host']}{base_path}"
    return ""  # fallback


def list_endpoints(spec, base):
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method in methods.keys():
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                endpoints.append({
                    "method": method.upper(),
                    "url": base + path,
                })
    return endpoints


def test_endpoints(endpoints):
    print("\nTesting APIs...\n")
    results = []
    for ep in endpoints:
        url = ep["url"]
        # Replace {id} style path params with 1
        if "{" in url:
            url = url.replace("{", "").replace("}", "")
        try:
            r = requests.request(ep["method"], url, timeout=10)
            status = r.status_code
        except Exception as e:
            status = f"ERROR: {str(e)}"

        results.append((ep["method"], url, status))
        print(f"{ep['method']:6}  {url:60}  ->  {status}")
    return results


def main():
    spec = load_openapi(SWAGGER_URL)
    base = extract_base(spec)
    print(f"Base URL detected: {base}")

    endpoints = list_endpoints(spec, base)
    print(f"\nFound {len(endpoints)} endpoints.\n")

    results = test_endpoints(endpoints)

    print("\n--- Summary ---")
    for method, url, status in results:
        print(f"{method} {url} = {status}")


if __name__ == "__main__":
    main()
