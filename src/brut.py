import requests
from bs4 import BeautifulSoup

# Configurations
DVWA_URL = 'http://localhost/DVWA'  # Change this to your DVWA URL
USERNAME = 'admin'
PASSWORD = 'password'  # Default DVWA credentials

# Start a session to maintain cookies
session = requests.Session()

def login(username, password):
    login_url = f"{DVWA_URL}/login.php"
    login_data = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    response = session.post(login_url, data=login_data)
    return 'Welcome' in response.text

def set_security_level(level):
    security_url = f"{DVWA_URL}/security.php"
    security_data = {
        'security': level,
        'seclev_submit': 'Submit'
    }
    session.get(security_url)  # Ensure we have the session cookie
    response = session.post(security_url, data=security_data)
    return level in response.text

def check_file_upload():
    upload_url = f"{DVWA_URL}/vulnerabilities/upload/"
    response = session.get(upload_url)
    if "File Upload" in response.text:
        print("[Low Risk] File Upload page is accessible without authentication.")
    else:
        print("[Low Risk] File Upload page requires authentication.")

def check_direct_url_access():
    direct_access_url = f"{DVWA_URL}/vulnerabilities/brute/"
    response = session.get(direct_access_url)
    if "Brute Force" in response.text:
        print("[Medium Risk] Direct URL access to Brute Force page is possible without proper authorization.")
    else:
        print("[Medium Risk] Brute Force page requires proper authorization.")

def check_admin_page_access():
    admin_url = f"{DVWA_URL}/vulnerabilities/exec/"
    response = session.get(admin_url)
    if "Command Execution" in response.text:
        print("[High Risk] Admin page is accessible without proper authorization.")
    else:
        print("[High Risk] Admin page requires proper authorization.")

def main():
    if not login(USERNAME, PASSWORD):
        print("Login failed. Check your credentials.")
        return

    # Test for different security levels
    for level in ['low', 'medium', 'high']:
        print(f"\nTesting at {level.capitalize()} security level:")
        if set_security_level(level):
            check_file_upload()
            check_direct_url_access()
            check_admin_page_access()
        else:
            print(f"Failed to set security level to {level}.")

if __name__ == "__main__":
    main()
