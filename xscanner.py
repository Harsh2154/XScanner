import requests
from bs4 import BeautifulSoup
import re
import time

# Function to display a banner
def show_banner():
    banner = """
    \033[38;5;3m
    ======================================

       XSS Vulnerability Advance Scanner

    ======================================
    \033[0m
    """
    print(banner)

# Function to sanitize and parse HTML
def sanitize_response(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    return soup.get_text()

# Function to detect and extract form fields
def get_form_fields(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Find forms and input fields
    forms = soup.find_all('form')
    if not forms:
        print("No forms found on the page.")
        return None
    
    # Extract form action and method
    form_details = []
    input_field_names = []
    total_input_fields = 0
    for form in forms:
        form_action = form.get('action')
        form_method = form.get('method', 'get').lower()
        input_fields = {}
        
        # Get all input fields from the form
        for input_tag in form.find_all(['input', 'textarea']):
            field_name = input_tag.get('name')
            if field_name:
                input_fields[field_name] = 'test'  # Initialize input fields with dummy data
                input_field_names.append(field_name)
                total_input_fields += 1  # Count the input field
        
        if input_fields:
            form_details.append({
                'action': form_action,
                'method': form_method,
                'fields': input_fields
            })
    # Print Total Detected Input Fields
    print(f"Total input fields found: {total_input_fields}")
    if input_field_names:
        print("Input fields detected: ", ', '.join(input_field_names))
    return form_details

from urllib.parse import urljoin

# Function to check for XSS and track vulnerable input fields
def check_xss(url, payload, form):
    # Construct full URL for form action
    form_action = urljoin(url, form['action']) if form['action'] else url
    form_method = form['method']
    
    # Set payloads for all detected input fields
    data = form['fields']
    for field in data:
        # Set the payload for each input field
        data[field] = payload
        
        # Make the appropriate request
        if form_method == 'post':
            response = requests.post(form_action, data=data)
        else:
            response = requests.get(form_action, params=data)
    
        # Sanitize the response
        sanitized_response = sanitize_response(response.text)
    
        # Check if the response contains potential XSS indicators
        if re.search(r'<script.*?>.*?</script>', response.text, re.IGNORECASE) or \
           re.search(r'on\w+\s*=\s*["\']*.*?["\']*', response.text, re.IGNORECASE):
            print(f"\033[91m[CRITICAL] Potential XSS vulnerability found in input field '{field}' with payload: {payload}\033[0m")
        else:
            print(f"No XSS vulnerability detected in input field '{field}' with payload: {payload}")


# Function to load payloads from a file
def load_payloads_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            # Read payloads from the file, one per line
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        exit()

# Main execution
if __name__ == "__main__":
    # Display the banner
    show_banner()

    # Get URL from user input
    url = input("Enter the target URL (e.g., http://example.com/vulnerable-endpoint): ")

    # Get payloads file path from user input
    payloads_file = input("Enter the payloads file path: ")

    # Load payloads from the specified file
    payloads = load_payloads_from_file(payloads_file)

    # Get form fields from the URL
    forms = get_form_fields(url)
    if not forms:
        print("No forms or input fields detected on the page.")
        exit()

    # Get rate limiting configuration from the user
    try:
        request_delay = float(input("Enter the delay in seconds between requests (e.g., 2 for 2 seconds): "))
    except ValueError:
        print("Invalid input. Defaulting to 2 seconds delay.")
        request_delay = 2  # Default delay if user input is invalid

    # Iterate over each form, field, and payload
    for form in forms:
        for payload in payloads:
            check_xss(url, payload, form)
            time.sleep(request_delay)
