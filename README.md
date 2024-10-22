# XScanner
This Python script is designed to detect Cross-Site Scripting (XSS) vulnerabilities in web applications by injecting common XSS payloads into form input fields. It identifies potential XSS vulnerabilities by checking responses for embedded scripts and event handlers.

## Features
Automatic Form Detection: The script scans the target webpage for forms and extracts all input fields, including <input> and <textarea>.

Payload Injection: XSS payloads can be provided via an external file, allowing for easy customization and testing.

Vulnerability Detection: Each form input is tested individually, and any potential XSS vulnerability is flagged based on script tags or event handlers in the response.

Detailed Reporting: The script shows the total number of input fields found, lists the detected fields, and reports whether vulnerabilities are found for each field using specific payloads.

Rate Limiting: Introduces a configurable delay between requests to avoid overwhelming the target server.

## How It Works
The script first scans the target URL for forms and identifies all available input fields.
The user provides a file with XSS payloads.
The script injects each payload into the detected input fields and sends requests to the server.
If the response contains <script> tags or event handlers, the script flags it as a potential XSS vulnerability.
The output includes:
The total number of input fields detected.
The names of input fields found.
A report indicating whether a vulnerability was found for each payload on specific fields.

## How to Use

1. Install Dependencies:
Install the required libraries by running the following command:

$ pip install requests beautifulsoup4

2. Prepare Payloads:
create a file (payloads.txt) containing XSS payloads, with one payload per line. Example payloads:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

3. Run the Script:
Execute the script by running:

$ python xss_scanner.py

4. View Results:
The script will output the total input fields found, their names, and any potential XSS vulnerabilities detected.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Harsh Sandigada - @Harsh2154


## Contributing
Feel free to submit issues, fork the repo, and send pull requests if you'd like to improve the script!
