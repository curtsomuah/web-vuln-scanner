import requests
from bs4 import BeautifulSoup
import threading

# Function to check security headers
def check_security_headers(url):
    headers_to_check = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-XSS-Protection",
        "X-Content-Type-Options"
    ]
    
    response = requests.get(url)
    missing_headers = [header for header in headers_to_check if header not in response.headers]

    if missing_headers:
        print(f"[!] Missing Security Headers: {', '.join(missing_headers)}")
    else:
        print("[+] All important security headers are present.")

# Function to check for open directories
def check_open_directories(url):
    common_dirs = ["admin/", "backup/", "uploads/", "config/", "database/"]
    
    for directory in common_dirs:
        full_url = url.rstrip("/") + "/" + directory
        response = requests.get(full_url)

        if response.status_code == 200:
            print(f"[!] Possible open directory found: {full_url}")

# Function to check for vulnerable forms
def check_forms_for_vulnerabilities(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")
    if not forms:
        print("[+] No forms found on the page.")
        return

    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        print(f"[+] Found form - Action: {action}, Method: {method}")

        inputs = form.find_all("input")
        for input_tag in inputs:
            input_type = input_tag.get("type", "text")
            input_name = input_tag.get("name", "Unnamed")
            print(f"  - Input field: {input_name} (Type: {input_type})")

# Function to test for XSS vulnerabilities
def test_xss_vulnerability(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    
    forms = soup.find_all("form")
    xss_payload = "<script>alert('XSS')</script>"
    
    for form in forms:
        action = form.get("action")
        full_url = url + action if action else url
        inputs = form.find_all("input")

        form_data = {}
        for input_tag in inputs:
            input_name = input_tag.get("name")
            if input_name:
                form_data[input_name] = xss_payload
        
        response = requests.post(full_url, data=form_data)
        if xss_payload in response.text:
            print(f"[!] XSS vulnerability detected in {full_url}")
        else:
            print(f"[+] No XSS vulnerability found in {full_url}")

# Function to test for SQL Injection vulnerabilities
def test_sql_injection(url):
    sql_payload = "' OR '1'='1"
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")
    
    for form in forms:
        action = form.get("action")
        full_url = url + action if action else url
        inputs = form.find_all("input")

        form_data = {}
        for input_tag in inputs:
            input_name = input_tag.get("name")
            if input_name:
                form_data[input_name] = sql_payload
        
        response = requests.post(full_url, data=form_data)
        if "error" in response.text.lower():
            print(f"[!] Possible SQL Injection vulnerability detected in {full_url}")
        else:
            print(f"[+] No SQL Injection vulnerability found in {full_url}")

# Function to run all scans in parallel
def run_scans(target_url):
    threads = []
    tests = [
        check_security_headers,
        check_open_directories,
        check_forms_for_vulnerabilities,
        test_xss_vulnerability,
        test_sql_injection
    ]
    
    for test in tests:
        thread = threading.Thread(target=test, args=(target_url,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\n[+] All security tests completed!")

# Menu function
def menu():
    print("\nSelect an option:")
    print("1. Check security headers")
    print("2. Check open directories")
    print("3. Check website forms for vulnerabilities")
    print("4. Test XSS vulnerabilities")
    print("5. Test SQL Injection vulnerabilities")
    print("6. Run all scans")
    
    choice = input("Enter your choice (1-6): ")

    if choice == "1":
        check_security_headers(target_url)
    elif choice == "2":
        check_open_directories(target_url)
    elif choice == "3":
        check_forms_for_vulnerabilities(target_url)
    elif choice == "4":
        test_xss_vulnerability(target_url)
    elif choice == "5":
        test_sql_injection(target_url)
    elif choice == "6":
        print("\n[+] Running all security tests...\n")
        run_scans(target_url)
    else:
        print("Invalid choice. Please try again.")

if __name__ == "__main__":
    target_url = input("Enter the website URL: ").strip()
    menu()

