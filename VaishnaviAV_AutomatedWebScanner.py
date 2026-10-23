
import requests
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

SECURITY_HEADERS = {
    "Content-Security-Policy":
        "Helps reduce certain cross-site scripting risks.",
    "Strict-Transport-Security":
        "Helps browsers use HTTPS for future connections.",
    "X-Content-Type-Options":
        "Helps prevent MIME type sniffing.",
    "X-Frame-Options":
        "Helps protect against clickjacking.",
    "Referrer-Policy":
        "Controls how much referrer information is shared.",
    "Permissions-Policy":
        "Controls access to browser features."
}


def scan_website(url):
    result = {
        "target": url,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Failed",
        "findings": [],
        "cors_review": {},
        "error": None
    }

    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        result["error"] = "Please enter a valid HTTP or HTTPS URL."
        return result

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "StudentWebScanner/1.0"}
        )

        result["status"] = "Completed"
        result["final_url"] = response.url
        result["http_status"] = response.status_code
        result["https"] = response.url.startswith("https://")

        for header, purpose in SECURITY_HEADERS.items():
            value = response.headers.get(header)

            if value:
                finding = {
                    "header": header,
                    "result": "Present",
                    "value": value,
                    "purpose": purpose
                }
            else:
                finding = {
                    "header": header,
                    "result": "Missing",
                    "value": None,
                    "purpose": purpose
                }

            result["findings"].append(finding)

        cors_origin = response.headers.get(
            "Access-Control-Allow-Origin"
        )
        cors_credentials = response.headers.get(
            "Access-Control-Allow-Credentials"
        )

        result["cors_review"] = {
            "allow_origin": cors_origin,
            "allow_credentials": cors_credentials,
            "note": (
                "Review the CORS settings in context. A wildcard origin "
                "or the presence of a CORS header alone does not prove "
                "a vulnerability."
            )
        }

    except requests.exceptions.RequestException as error:
        result["error"] = str(error)

    return result


def save_report(result):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"scan_report_{timestamp}.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    return report_file


def display_results(result):
    print("\n" + "=" * 50)
    print("       AUTOMATED WEBSITE SECURITY SCANNER")
    print("=" * 50)

    print(f"Target: {result['target']}")
    print(f"Status: {result['status']}")

    if result["error"]:
        print(f"Error: {result['error']}")
        return

    print(f"HTTP Status Code: {result['http_status']}")
    print(f"HTTPS: {'Yes' if result['https'] else 'No'}")

    print("\nSECURITY HEADER CHECK")
    print("-" * 50)

    for finding in result["findings"]:
        print(f"{finding['header']}: {finding['result']}")

        if finding["result"] == "Missing":
            print(f"  Purpose: {finding['purpose']}")

    print("\nCORS REVIEW")
    print("-" * 50)

    cors = result["cors_review"]
    print(
        "Access-Control-Allow-Origin:",
        cors["allow_origin"] or "Not present"
    )
    print(
        "Access-Control-Allow-Credentials:",
        cors["allow_credentials"] or "Not present"
    )
    print(cors["note"])

    print("\nNote: Missing headers need manual review.")
    print("A missing header does not automatically mean a website is vulnerable.")


def main():
    print("Automated Website Security Scanner")
    print("Use only on websites you own or have permission to test.")

    url = input("\nEnter website URL: ").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = scan_website(url)
    display_results(result)

    report_file = save_report(result)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
