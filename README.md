
# Automated Web Scanner

## About the Project

This project is a simple Python-based tool that checks some common security headers used by websites. It also displays basic information about the website and reviews the CORS headers returned by the server.

I made this project to understand how website security headers work and how a small Python program can help with basic security checks.

## Features

- Checks common HTTP security headers.
- Displays the HTTP status code.
- Checks whether the final website URL uses HTTPS.
- Reviews the Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers.
- Displays missing security headers.
- Saves the scan results in JSON format.
- Handles connection errors and invalid URLs.

## Technologies Used

- Python
- Requests library
- JSON
- VS Code

## Project Structure

```text
automated-web-scanner/
├── scanner.py
├── requirements.txt
├── README.md
├── project-report.md
└── reports/
    └── scan_report_YYYYMMDD_HHMMSS.json
```

## Requirements

- Python 3
- Internet connection
- Requests library

## Installation

Open the project folder in VS Code and run:

```bash
python -m pip install -r requirements.txt
```

## How to Run

Run the following command in the terminal:

```bash
python scanner.py
```

Enter a website URL when prompted. For testing, use a website you own or have permission to assess.

The scanner displays the results in the terminal and saves them in the reports folder.

## How It Works

The program sends an HTTP request to the entered website and reads the response headers. It checks whether selected security headers are present and displays their status. It also records basic CORS-related response headers.

The scan results are saved in a JSON file so they can be reviewed later.

## Limitations

- The scanner checks only a selected set of response headers.
- A missing security header does not automatically mean that a website is vulnerable.
- The CORS review is preliminary and does not prove that a CORS vulnerability exists.
- The tool does not test for every type of web application vulnerability.

## Conclusion

This project helped me understand HTTP response headers, basic website security checks, Python requests and JSON report generation. It can be extended in the future with a graphical interface and additional security checks.

## Responsible Use

Use this tool only on websites you own or have permission to test.
