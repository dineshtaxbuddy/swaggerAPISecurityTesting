import requests
import json
import csv
import os
from datetime import datetime
from typing import Dict, Any, List

# Load configuration
def load_config():
    """Load configuration from config.json file"""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise Exception(f"Configuration file not found at {config_path}")
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid JSON in config file: {e}")

CONFIG = load_config()


def is_token_expired(status_code: int, response_text: str) -> bool:
    """Check if the response indicates token expiration"""
    if status_code in [401, 403]:
        # Check for common token expiration messages
        expiration_keywords = [
            "expired", "token", "unauthorized", "forbidden",
            "invalid token", "authentication", "jwt"
        ]
        response_lower = response_text.lower()
        return any(keyword in response_lower for keyword in expiration_keywords)
    return False


def prompt_for_new_token() -> str:
    """Prompt user to enter a new bearer token"""
    print("\n" + "="*60)
    print("TOKEN EXPIRED - NEW TOKEN REQUIRED")
    print("="*60)
    print("The current authentication token has expired.")
    print("Please enter a new bearer token to continue testing.")
    print("Format: Bearer <your-token>")
    print("="*60)

    while True:
        new_token = input("\nEnter new token (or 'q' to quit): ").strip()

        if new_token.lower() == 'q':
            print("Exiting due to token expiration...")
            exit(0)

        # Validate token format
        if not new_token:
            print("Error: Token cannot be empty. Please try again.")
            continue

        # Add "Bearer " prefix if not present
        if not new_token.startswith("Bearer "):
            new_token = f"Bearer {new_token}"

        # Basic validation - should have Bearer and a token part
        parts = new_token.split(" ")
        if len(parts) >= 2 and len(parts[1]) > 20:
            return new_token
        else:
            print("Error: Invalid token format. Please enter a valid bearer token.")


def update_config_token(new_token: str) -> None:
    """Update the bearer token in config.json file and global CONFIG"""
    global CONFIG

    config_path = os.path.join(os.path.dirname(__file__), "config.json")

    try:
        # Update the config dictionary
        CONFIG["bearer_token"] = new_token

        # Write back to config.json
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(CONFIG, f, indent=2)

        print(f"\n✓ Token updated successfully in config.json")
        print("✓ Continuing API testing with new token...\n")

    except Exception as e:
        print(f"Warning: Could not update config.json: {e}")
        print("Continuing with new token in memory only...\n")


def handle_token_expiration(status_code: int, response_text: str) -> bool:
    """
    Check if token expired and handle refresh if needed.
    Returns True if token was refreshed, False otherwise.
    """
    if is_token_expired(status_code, response_text):
        new_token = prompt_for_new_token()
        update_config_token(new_token)
        return True
    return False


def display_service_menu() -> Dict[str, Any]:
    """Display service selection menu and return selected service configuration"""
    services = CONFIG.get("services", {})

    if not services:
        raise Exception("No services configured in config.json")

    print("\n" + "="*60)
    print("SELECT SERVICE TO TEST")
    print("="*60)

    for key in sorted(services.keys()):
        service = services[key]
        print(f"Option {key}: {service['name']:<15} - {service['description']}")

    print("="*60)

    while True:
        choice = input("\nEnter your choice (or 'q' to quit): ").strip()

        if choice.lower() == 'q':
            print("Exiting...")
            exit(0)

        if choice in services:
            selected_service = services[choice]
            print(f"\nYou selected: {selected_service['name']}")
            return selected_service
        else:
            print(f"Invalid choice. Please select from {', '.join(sorted(services.keys()))}")


def display_testing_type_menu() -> str:
    """Display testing type menu and return selected testing type"""
    print("\n" + "="*60)
    print("SELECT TESTING TYPE TO PERFORM")
    print("="*60)
    print("Option 1: Normal API Testing")
    print("           - Test all endpoints with authentication")
    print("Option 2: Authentication Bypass Testing")
    print("           - Test if APIs work without authentication token")
    print("Option 3: Rate Limiting Testing")
    print(f"           - Test each API {CONFIG.get('rate_limit_count', 3)} times to check rate limits")
    print("="*60)

    while True:
        choice = input("\nEnter your choice (1-3, or 'q' to quit): ").strip()

        if choice.lower() == 'q':
            print("Exiting...")
            exit(0)

        if choice == '1':
            print("\nYou selected: Normal API Testing")
            return "normal"
        elif choice == '2':
            print("\nYou selected: Authentication Bypass Testing")
            return "auth_bypass"
        elif choice == '3':
            print("\nYou selected: Rate Limiting Testing")
            return "rate_limit"
        else:
            print("Invalid choice. Please select 1, 2, or 3")


def get_openapi_json(service_url: str):
    """Fetch OpenAPI specification from the configured URL"""
    headers = {
        "Authorization": CONFIG["bearer_token"],
        "Accept": "application/json"
    }
    try:
        r = requests.get(service_url, headers=headers, timeout=CONFIG.get("timeout", 30))
        r.raise_for_status()
        openapi_json = r.json()
        print("JSON KEYS:", openapi_json.keys())  # DEBUG
        return openapi_json
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch OpenAPI spec: {e}")
    except json.JSONDecodeError:
        raise Exception("Response is not valid JSON")


def generate_example_value(param_schema: Dict[str, Any]) -> Any:
    """Generate example value based on OpenAPI schema"""
    param_type = param_schema.get("type", "string")

    # Check for example values first
    if "example" in param_schema:
        return param_schema["example"]
    if "default" in param_schema:
        return param_schema["default"]

    # Check for enum values
    if "enum" in param_schema and param_schema["enum"]:
        return param_schema["enum"][0]

    # Generate based on type
    type_examples = {
        "string": "test_value",
        "integer": 1,
        "number": 1.0,
        "boolean": True,
        "array": [],
        "object": {}
    }

    return type_examples.get(param_type, "test_value")


def generate_request_body(body_schema: Dict[str, Any]) -> Dict[str, Any]:
    """Generate request body from OpenAPI schema"""
    if not body_schema:
        return {}

    content = body_schema.get("content", {})
    json_content = content.get("application/json", {})
    schema = json_content.get("schema", {})

    if not schema:
        return {}

    # Handle schema reference
    if "$ref" in schema:
        # For now, return empty object (can be enhanced to resolve refs)
        return {}

    # Generate body based on schema properties
    body = {}
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    for prop_name, prop_schema in properties.items():
        # Only include required fields or all fields
        body[prop_name] = generate_example_value(prop_schema)

    return body


def resolve_path_parameters(path: str, parameters: List[Dict[str, Any]]) -> str:
    """Replace path parameters with example values"""
    resolved_path = path

    for param in parameters:
        if param.get("in") == "path":
            param_name = param.get("name")
            param_value = generate_example_value(param.get("schema", {}))
            resolved_path = resolved_path.replace(f"{{{param_name}}}", str(param_value))

    return resolved_path


def extract_query_parameters(parameters: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract query parameters from OpenAPI parameters"""
    query_params = {}

    for param in parameters:
        if param.get("in") == "query":
            param_name = param.get("name")
            # Only include required query parameters
            if param.get("required", False):
                param_value = generate_example_value(param.get("schema", {}))
                query_params[param_name] = param_value

    return query_params


def extract_headers(parameters: List[Dict[str, Any]]) -> Dict[str, str]:
    """Extract header parameters from OpenAPI parameters"""
    headers = {}

    for param in parameters:
        if param.get("in") == "header":
            param_name = param.get("name")
            param_value = str(generate_example_value(param.get("schema", {})))
            headers[param_name] = param_value

    return headers


def generate_curl_command(method: str, url: str, headers: Dict[str, str], query_params: Dict[str, Any] = None, request_body: Dict[str, Any] = None) -> str:
    """Generate cURL command from request parameters"""
    curl_parts = ["curl -X", method.upper()]

    # Add URL with query parameters
    full_url = url
    if query_params:
        query_string = "&".join([f"{k}={v}" for k, v in query_params.items()])
        full_url = f"{url}?{query_string}"
    curl_parts.append(f'"{full_url}"')

    # Add headers
    for header_name, header_value in headers.items():
        curl_parts.append(f'-H "{header_name}: {header_value}"')

    # Add request body if present
    if request_body:
        body_json = json.dumps(request_body).replace('"', '\\"')
        curl_parts.append(f'-d "{body_json}"')

    return " ".join(curl_parts)


def run_all_api(openapi: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute all API endpoints defined in OpenAPI spec"""
    # Fetch base URL from "servers"
    servers = openapi.get("servers", [])
    if not servers:
        raise Exception("No 'servers' key found in OpenAPI JSON")

    base_url = servers[0]["url"]
    print(f"Base URL: {base_url}\n")

    results = []
    total_endpoints = sum(len(methods) for methods in openapi["paths"].values())
    current = 0

    for path, methods in openapi["paths"].items():
        for method, details in methods.items():
            current += 1

            # Skip non-HTTP methods (like "parameters", "servers", etc.)
            if method not in ["get", "post", "put", "patch", "delete", "head", "options"]:
                continue

            # Get parameters
            parameters = details.get("parameters", [])

            # Resolve path parameters
            resolved_path = resolve_path_parameters(path, parameters)
            url = base_url + resolved_path

            # Extract query parameters
            query_params = extract_query_parameters(parameters)

            # Extract custom headers
            custom_headers = extract_headers(parameters)

            # Prepare headers
            headers = {
                "Authorization": CONFIG["bearer_token"],
                "Content-Type": "application/json"
            }
            headers.update(custom_headers)

            # Generate request body for POST/PUT/PATCH
            request_body = None
            if method.lower() in ["post", "put", "patch"]:
                body_schema = details.get("requestBody", {})
                request_body = generate_request_body(body_schema)

            print(f"[{current}/{total_endpoints}] {method.upper()} {url}")
            if query_params:
                print(f"  Query params: {query_params}")
            if request_body:
                print(f"  Body: {json.dumps(request_body)[:100]}...")

            # Generate cURL command
            curl_command = generate_curl_command(method, url, headers, query_params, request_body)

            # Execute request with token refresh retry logic
            start_time = datetime.now()
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=query_params,
                    json=request_body if request_body else None,
                    timeout=CONFIG.get("timeout", 30)
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                # Truncate response
                max_length = CONFIG.get("max_response_length", 300)
                response_text = response.text[:max_length]
                if len(response.text) > max_length:
                    response_text += "... (truncated)"

                # Check for token expiration and handle refresh
                if handle_token_expiration(response.status_code, response.text):
                    # Update headers with new token
                    headers["Authorization"] = CONFIG["bearer_token"]

                    # Retry the request with new token
                    print(f"  Retrying with new token...")
                    start_time = datetime.now()
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        params=query_params,
                        json=request_body if request_body else None,
                        timeout=CONFIG.get("timeout", 30)
                    )
                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()

                    response_text = response.text[:max_length]
                    if len(response.text) > max_length:
                        response_text += "... (truncated)"

                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "duration_sec": round(duration, 2),
                    "response": response_text,
                    "error": "",
                    "curl": curl_command
                })

                print(f"  Status: {response.status_code} | Duration: {duration:.2f}s\n")

            except requests.exceptions.Timeout:
                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": "TIMEOUT",
                    "duration_sec": CONFIG.get("timeout", 30),
                    "response": "",
                    "error": f"Request timeout after {CONFIG.get('timeout', 30)}s",
                    "curl": curl_command
                })
                print(f"  Status: TIMEOUT\n")

            except Exception as e:
                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": "ERROR",
                    "duration_sec": 0,
                    "response": "",
                    "error": str(e),
                    "curl": curl_command
                })
                print(f"  Status: ERROR - {str(e)}\n")

    return results


def run_auth_bypass_test(openapi: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute all API endpoints WITHOUT authentication token to test security"""
    servers = openapi.get("servers", [])
    if not servers:
        raise Exception("No 'servers' key found in OpenAPI JSON")

    base_url = servers[0]["url"]
    print(f"Base URL: {base_url}\n")
    print("WARNING: Testing APIs WITHOUT authentication token\n")

    results = []
    total_endpoints = sum(len(methods) for methods in openapi["paths"].values())
    current = 0

    for path, methods in openapi["paths"].items():
        for method, details in methods.items():
            current += 1

            # Skip non-HTTP methods
            if method not in ["get", "post", "put", "patch", "delete", "head", "options"]:
                continue

            parameters = details.get("parameters", [])
            resolved_path = resolve_path_parameters(path, parameters)
            url = base_url + resolved_path
            query_params = extract_query_parameters(parameters)
            custom_headers = extract_headers(parameters)

            # Prepare headers WITHOUT Authorization token
            headers = {
                "Content-Type": "application/json"
            }
            headers.update(custom_headers)

            # Generate request body for POST/PUT/PATCH
            request_body = None
            if method.lower() in ["post", "put", "patch"]:
                body_schema = details.get("requestBody", {})
                request_body = generate_request_body(body_schema)

            print(f"[{current}/{total_endpoints}] {method.upper()} {url} (NO AUTH)")

            # Generate cURL command (without auth token)
            curl_command = generate_curl_command(method, url, headers, query_params, request_body)

            # Execute request
            start_time = datetime.now()
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    params=query_params,
                    json=request_body if request_body else None,
                    timeout=CONFIG.get("timeout", 30)
                )

                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                max_length = CONFIG.get("max_response_length", 300)
                response_text = response.text[:max_length]
                if len(response.text) > max_length:
                    response_text += "... (truncated)"

                # Flag security issue if API succeeds without auth
                security_issue = ""
                if response.status_code in [200, 201, 202, 204]:
                    security_issue = "SECURITY WARNING: API accessible without authentication!"
                    print(f"  Status: {response.status_code} | ⚠️  SECURITY ISSUE!")
                elif response.status_code in [401, 403]:
                    security_issue = "Protected - Auth required (Expected behavior)"
                    print(f"  Status: {response.status_code} | ✓ Protected")
                else:
                    print(f"  Status: {response.status_code}")

                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "duration_sec": round(duration, 2),
                    "response": response_text,
                    "error": "",
                    "security_note": security_issue,
                    "curl": curl_command
                })

            except requests.exceptions.Timeout:
                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": "TIMEOUT",
                    "duration_sec": CONFIG.get("timeout", 30),
                    "response": "",
                    "error": f"Request timeout after {CONFIG.get('timeout', 30)}s",
                    "security_note": "",
                    "curl": curl_command
                })
                print(f"  Status: TIMEOUT\n")

            except Exception as e:
                results.append({
                    "method": method.upper(),
                    "path": path,
                    "url": url,
                    "status_code": "ERROR",
                    "duration_sec": 0,
                    "response": "",
                    "error": str(e),
                    "security_note": "",
                    "curl": curl_command
                })
                print(f"  Status: ERROR - {str(e)}\n")

            print()

    return results


def run_rate_limit_test(openapi: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute each API endpoint multiple times to test rate limiting"""
    servers = openapi.get("servers", [])
    if not servers:
        raise Exception("No 'servers' key found in OpenAPI JSON")

    base_url = servers[0]["url"]
    rate_limit_count = CONFIG.get("rate_limit_count", 3)

    print(f"Base URL: {base_url}\n")
    print(f"Testing Rate Limiting: Each API will be called {rate_limit_count} times\n")

    results = []
    total_endpoints = sum(len(methods) for methods in openapi["paths"].values())
    current = 0

    for path, methods in openapi["paths"].items():
        for method, details in methods.items():
            current += 1

            # Skip non-HTTP methods
            if method not in ["get", "post", "put", "patch", "delete", "head", "options"]:
                continue

            parameters = details.get("parameters", [])
            resolved_path = resolve_path_parameters(path, parameters)
            url = base_url + resolved_path
            query_params = extract_query_parameters(parameters)
            custom_headers = extract_headers(parameters)

            # Prepare headers with auth
            headers = {
                "Authorization": CONFIG["bearer_token"],
                "Content-Type": "application/json"
            }
            headers.update(custom_headers)

            # Generate request body for POST/PUT/PATCH
            request_body = None
            if method.lower() in ["post", "put", "patch"]:
                body_schema = details.get("requestBody", {})
                request_body = generate_request_body(body_schema)

            print(f"[{current}/{total_endpoints}] {method.upper()} {url}")

            # Generate cURL command
            curl_command = generate_curl_command(method, url, headers, query_params, request_body)

            # Execute request multiple times
            for attempt in range(1, rate_limit_count + 1):
                start_time = datetime.now()
                try:
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        params=query_params,
                        json=request_body if request_body else None,
                        timeout=CONFIG.get("timeout", 30)
                    )

                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()

                    max_length = CONFIG.get("max_response_length", 300)
                    response_text = response.text[:max_length]
                    if len(response.text) > max_length:
                        response_text += "... (truncated)"

                    # Check for token expiration and handle refresh
                    if handle_token_expiration(response.status_code, response.text):
                        # Update headers with new token
                        headers["Authorization"] = CONFIG["bearer_token"]

                        # Retry the request with new token
                        print(f"  Retrying attempt {attempt} with new token...")
                        start_time = datetime.now()
                        response = requests.request(
                            method,
                            url,
                            headers=headers,
                            params=query_params,
                            json=request_body if request_body else None,
                            timeout=CONFIG.get("timeout", 30)
                        )
                        end_time = datetime.now()
                        duration = (end_time - start_time).total_seconds()

                        response_text = response.text[:max_length]
                        if len(response.text) > max_length:
                            response_text += "... (truncated)"

                    # Check for rate limiting response
                    rate_limit_note = ""
                    if response.status_code == 429:
                        rate_limit_note = f"Rate limit detected on attempt {attempt}"
                        print(f"  Attempt {attempt}/{rate_limit_count}: Status {response.status_code} | ⚠️  RATE LIMITED")
                    elif response.status_code in [200, 201, 202, 204]:
                        rate_limit_note = f"Success on attempt {attempt}"
                        print(f"  Attempt {attempt}/{rate_limit_count}: Status {response.status_code} | Duration: {duration:.2f}s")
                    else:
                        rate_limit_note = f"Response {response.status_code} on attempt {attempt}"
                        print(f"  Attempt {attempt}/{rate_limit_count}: Status {response.status_code}")

                    results.append({
                        "method": method.upper(),
                        "path": path,
                        "url": url,
                        "attempt": attempt,
                        "status_code": response.status_code,
                        "duration_sec": round(duration, 2),
                        "response": response_text,
                        "error": "",
                        "rate_limit_note": rate_limit_note,
                        "curl": curl_command
                    })

                except requests.exceptions.Timeout:
                    results.append({
                        "method": method.upper(),
                        "path": path,
                        "url": url,
                        "attempt": attempt,
                        "status_code": "TIMEOUT",
                        "duration_sec": CONFIG.get("timeout", 30),
                        "response": "",
                        "error": f"Request timeout after {CONFIG.get('timeout', 30)}s",
                        "rate_limit_note": f"Timeout on attempt {attempt}",
                        "curl": curl_command
                    })
                    print(f"  Attempt {attempt}/{rate_limit_count}: TIMEOUT")

                except Exception as e:
                    results.append({
                        "method": method.upper(),
                        "path": path,
                        "url": url,
                        "attempt": attempt,
                        "status_code": "ERROR",
                        "duration_sec": 0,
                        "response": "",
                        "error": str(e),
                        "rate_limit_note": f"Error on attempt {attempt}",
                        "curl": curl_command
                    })
                    print(f"  Attempt {attempt}/{rate_limit_count}: ERROR - {str(e)}")

            print()

    return results


def save_report(results: List[Dict[str, Any]], service_name: str, test_type: str = "normal") -> None:
    """Save API test results to CSV file with enhanced reporting"""
    # Create report directory if it doesn't exist
    report_dir = CONFIG.get("report_directory", "results")
    os.makedirs(report_dir, exist_ok=True)

    # Generate report filename with service name, test type, and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(report_dir, f"{service_name}_{test_type}_report_{timestamp}.csv")

    with open(report_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Different headers based on test type
        if test_type == "auth_bypass":
            writer.writerow(["METHOD", "PATH", "URL", "STATUS_CODE", "DURATION_SEC", "ERROR", "SECURITY_NOTE", "CURL", "RESPONSE"])
            for r in results:
                writer.writerow([
                    r.get("method", ""),
                    r.get("path", ""),
                    r.get("url", ""),
                    r.get("status_code", ""),
                    r.get("duration_sec", ""),
                    r.get("error", ""),
                    r.get("security_note", ""),
                    r.get("curl", ""),
                    r.get("response", "")
                ])
        elif test_type == "rate_limit":
            writer.writerow(["METHOD", "PATH", "URL", "ATTEMPT", "STATUS_CODE", "DURATION_SEC", "ERROR", "RATE_LIMIT_NOTE", "CURL", "RESPONSE"])
            for r in results:
                writer.writerow([
                    r.get("method", ""),
                    r.get("path", ""),
                    r.get("url", ""),
                    r.get("attempt", ""),
                    r.get("status_code", ""),
                    r.get("duration_sec", ""),
                    r.get("error", ""),
                    r.get("rate_limit_note", ""),
                    r.get("curl", ""),
                    r.get("response", "")
                ])
        else:  # normal
            writer.writerow(["METHOD", "PATH", "URL", "STATUS_CODE", "DURATION_SEC", "ERROR", "CURL", "RESPONSE"])
            for r in results:
                writer.writerow([
                    r.get("method", ""),
                    r.get("path", ""),
                    r.get("url", ""),
                    r.get("status_code", ""),
                    r.get("duration_sec", ""),
                    r.get("error", ""),
                    r.get("curl", ""),
                    r.get("response", "")
                ])

    print(f"\n{'='*60}")
    print(f"Report generated: {report_file}")
    print(f"{'='*60}")


def print_summary(results: List[Dict[str, Any]]) -> None:
    """Print summary statistics of the API test results"""
    total = len(results)
    success = sum(1 for r in results if isinstance(r["status_code"], int) and 200 <= r["status_code"] < 300)
    client_errors = sum(1 for r in results if isinstance(r["status_code"], int) and 400 <= r["status_code"] < 500)
    server_errors = sum(1 for r in results if isinstance(r["status_code"], int) and 500 <= r["status_code"] < 600)
    timeouts = sum(1 for r in results if r["status_code"] == "TIMEOUT")
    errors = sum(1 for r in results if r["status_code"] == "ERROR")

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total Endpoints:     {total}")
    print(f"Success (2xx):       {success}")
    print(f"Client Errors (4xx): {client_errors}")
    print(f"Server Errors (5xx): {server_errors}")
    print(f"Timeouts:            {timeouts}")
    print(f"Errors:              {errors}")
    print(f"{'='*60}\n")


def main():
    """Main execution function with enhanced error handling"""
    print("="*60)
    print("API TESTING TOOL")
    print("="*60)

    try:
        # Display service selection menu
        selected_service = display_service_menu()
        service_name = selected_service["name"]
        service_url = selected_service["openapi_url"]

        # Display testing type selection menu
        test_type = display_testing_type_menu()

        # Fetch OpenAPI specification
        print(f"\nFetching OpenAPI specification for {service_name}...")
        openapi = get_openapi_json(service_url)

        # Execute appropriate test based on selected type
        print("\nExecuting API endpoints...")
        if test_type == "normal":
            results = run_all_api(openapi)
        elif test_type == "auth_bypass":
            results = run_auth_bypass_test(openapi)
        elif test_type == "rate_limit":
            results = run_rate_limit_test(openapi)
        else:
            raise Exception(f"Unknown test type: {test_type}")

        # Print summary
        print_summary(results)

        # Save report with service name and test type
        save_report(results, service_name, test_type)

        print(f"\n{service_name} API testing ({test_type}) completed successfully!")
        print("Done!")

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        return

    except Exception as e:
        print(f"\n\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()
