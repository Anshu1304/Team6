import requests

# Configuration
base_url = 'http://localhost/dvwa'  # Replace with the actual URL of your DVWA installation
login_url = f'{base_url}/login.php'
restricted_urls = [
    ('Admin Panel', f'{base_url}/vulnerabilities/csrf/'),
    ('File Inclusion', f'{base_url}/vulnerabilities/fi/'),
    ('Command Injection', f'{base_url}/vulnerabilities/exec/')
]

# User credentials
users = {
    'admin': 'password',      # Admin credentials
    'user': 'password'        # Regular user credentials
}

# Function to login to DVWA
def login(username, password):
    session = requests.Session()
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    response = session.post(login_url, data=login_data)
    if 'login.php' not in response.url:  # Check if login was successful
        return session
    return None

# Function to test access to restricted resources
def test_access(session, url):
    response = session.get(url)
    return response.status_code, response.text

# Main workflow
results = []

for role, (username, password) in users.items():
    session = login(username, password)
    if session:
        for resource, url in restricted_urls:
            status_code, response_text = test_access(session, url)
            if status_code == 200 and 'Access Denied' not in response_text:
                results.append(f'Broken Access Control Detected: {role} can access {resource} at {url}')
            else:
                results.append(f'Access Control Working: {role} cannot access {resource} at {url}')
    else:
        results.append(f'Failed to login with {role} credentials.')

# Output results to text file
with open('access_control_results.txt', 'w') as file:
    for result in results:
        file.write(result + '\n')

print("Testing completed. Results saved to 'access_control_results.txt'.")
