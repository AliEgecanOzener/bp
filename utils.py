import time
import socket
import random
import string
import requests
import validators
import cloudscraper
from termcolor import colored
from urllib.parse import quote, urlparse, urlunparse

def url_validation_check(url):
    if validators.url(url):
        return True
    else:
        return False
 

def convert_string_to_dict(data):
    if data is None:
        return None
    if isinstance(data, dict):
        return dict(data)
    if not isinstance(data, str):
        return None

    data = data.strip()
    converted = {}
    pairs = data.split("\n")

    for pair in pairs:
        pair = pair.strip()
        if ":" in pair:
            key, value = pair.split(":", 1)
            key = key.strip()
            value = value.strip()
            converted[key] = value
        elif "=" in pair:
            key, value = pair.split("=", 1)
            key = key.strip()
            value = value.strip()
            converted[key] = value

    return converted


def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters, k=length)).lower()


def reformat_url(url):
    if not url.endswith('='):
        new_url = ""
        fequal = False
        for char in reversed(url):
            if char == '=':
                fequal = True
            if fequal:
                new_url = char + new_url
        return new_url
    else:
        return url



def get_query(url, cookie, header, retries=5, delay=5):
    session = cloudscraper.create_scraper()

    if isinstance(cookie, str):
        cookie = convert_string_to_dict(cookie) or {}

    if isinstance(header, str):
        header = convert_string_to_dict(header) or {}

    for attempt in range(retries):
        try:
            response = session.get(url, cookies=cookie, headers=header, timeout=20)
            return response
        except requests.exceptions.ReadTimeout:
            print(colored(f"[-] Read timeout. Retry {attempt + 1}/{retries}", "yellow"))
            time.sleep(delay)
        except requests.exceptions.Timeout:
            print(colored("[-] Request timed out.", "red"))
            raise
        except requests.exceptions.ConnectionError:
            print(colored("[-] Connection error occurred.", "red"))
            raise
        except requests.exceptions.HTTPError as e:
            print(colored(f"[-] HTTP error: {e}", "red"))
            raise
        except requests.exceptions.RequestException as e:
            print(colored(f"[-] Unexpected error: {e}", "red"))
            raise

    print(colored("[-] Failed after retries.", "red"))
    return None


def post_query(url, cookie, header, data, file):
    if isinstance(cookie, str):
        cookie = convert_string_to_dict(cookie) or {}

    if isinstance(header, str):
        header = convert_string_to_dict(header) or {}

    try:
        session = cloudscraper.create_scraper()

        if file:
            response = session.post(url, cookies=cookie, headers=header, data=data, files=file, timeout=10)
        else:
            response = session.post(url, cookies=cookie, headers=header, data=data, timeout=10)

        return response

    except requests.exceptions.Timeout:
        print(colored("[-] Request timed out.", "red"))
    except requests.exceptions.ConnectionError:
        print(colored("[-] Connection error occurred.", "red"))
    except requests.exceptions.HTTPError as e:
        print(colored(f"[-] HTTP error: {e}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Unexpected error: {e}", "red"))


def cmd_output(cmd):

    first_delimiter = "first_delimiter"
    last_delimiter = "last_delimiter"
    if first_delimiter in cmd and last_delimiter in cmd:
        cmd_start = cmd.split("first_delimiter")[-1]
        output = cmd_start.split("last_delimiter")[0]
        return output
    else :
        return None
    

def get_random_user_agent():
    try:
        with open("dir/random_agents", "r", encoding="utf-8") as file:
            user_agents = [line.strip() for line in file if line.strip()]
        return random.choice(user_agents).strip() if user_agents else None
    except FileNotFoundError:
        print(colored("[-] File Not found.", "red"))
        return None


def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        sock.connect((host, port))
    except (socket.timeout, socket.error):

        return False
    else:
        return True
    finally:
        sock.close()


def get_port():
    while True:
        port_input = input(colored("\n[*] Enter a port number (default is 4545): ", "yellow")).strip()
        port = int(port_input) if port_input else 4545

        if 1 <= port <= 65535:
            if check_port("127.0.0.1", port):
                print(colored(f"[*] Port {port} is already in use. Try another port.", "yellow"))
            else:
                return port
        else:
            print(colored("[!] Invalid port number. Please enter a valid port between 1 and 65535.", "red"))

def get_ip():
    while True:
        ip_input = input(colored("\n[*] Please enter the IP address to connect to: ", "yellow")).strip()
        validators.ipv4(ip_input)
        return ip_input


def parse_comma(text):
    parameters = []
    if text:
       text = text.split(",")
    else:
        return None

    for t in text:
        t = t.strip()
        parameters.append(t)
    if parameters:
       return parameters
    else:
        return None

def lowered(text):
    if text:
       for t in text:
           t = t.lower()
       return text
    else:
        return None


def dict_to_string(data):
    return '&'.join(f"{key}={value}" for key, value in data.items())


def double_url_encode(s):
    return quote(quote(s))

def parse_headers(header_string):
    headers = {}
    for item in header_string.split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        headers[key.strip()] = value.strip()
    return headers


def http_basic_auth(url, creds):
    parsed = urlparse(url)

    if not parsed.netloc or ":" not in creds:
        return url, None

    host = parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    auth_netloc = f"{creds}@{host}{port}"

    new_url = urlunparse((
        parsed.scheme,
        auth_netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    headers = {"User-Agent": get_random_user_agent()}
    try:
        resp = requests.get(new_url, headers=headers, timeout=10)
        set_cookie = resp.headers.get('Set-Cookie')
        return new_url, set_cookie
    except:
        return new_url, None


http_basic_auth("http://10.10.10.18/WebGoat/attack?Screen=150&menu=400","guest:guest")
