import re
import random
import string
import requests
import validators
from termcolor import colored

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
            key, value = pair.split(":")
            key = key.strip()
            value = value.strip()
            converted[key] = value
        elif "=" in pair:
            key, value = pair.split("=")
            key = key.strip()
            value = value.strip()
            converted[key] = value

    return converted


def user_parameter_extract(string):
 user_parameter_set = set()
 if string != '':
  for parameter in string.split(','):
   parameter = parameter.strip()
   user_parameter_set.add(parameter)
  return user_parameter_set
 else:
  return None
 

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


def get_query(url, cookie, header):

    if isinstance(cookie, str):
        cookie = convert_string_to_dict(cookie) or {}

    if isinstance(header, str):
        header = convert_string_to_dict(header) or {}

    try:
        session = requests.Session()
        response = session.get(url, cookies=cookie, headers=header, timeout=10)
        if response.status_code != 200:
            print(response.status_code)
        return response if response.status_code == 200 else None

    except requests.exceptions.Timeout:
        print(colored("[-] Request timed out.", "red"))

    except requests.exceptions.ConnectionError:
        print(colored("[-] Connection error occurred.", "red"))
    except requests.exceptions.HTTPError as e:
        print(colored(f"[-] HTTP error: {e}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Unexpected error: {e}", "red"))


def post_query(url, cookie, header, data):

    if isinstance(cookie, str):
        cookie = convert_string_to_dict(cookie) or {}

    if isinstance(header, str):
        header = convert_string_to_dict(header) or {}

    try:
        session = requests.Session()
        response = session.post(url, cookies=cookie, headers=header, data=data, timeout=10)

        return response if response.status_code == 200 else None

    except requests.exceptions.Timeout:
        print(colored("[-] Request timed out.", "red"))
    except requests.exceptions.ConnectionError:
        print(colored("[-] Connection error occurred.", "red"))
    except requests.exceptions.HTTPError as e:
        print(colored(f"[-] HTTP error: {e}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[-] Unexpected error: {e}", "red"))


def cmd_output(cmd):
    cmd = cmd.replace("\n","").replace("\r","")
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
        return convert_string_to_dict(random.choice(user_agents)) if user_agents else None
    except FileNotFoundError:
        print(colored("[-] File Not found.","red"))
        return None