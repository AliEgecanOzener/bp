#import socket
#import ssl
#import re
import nmap
import requests
from urllib.parse import urlparse
from utils import get_query, get_random_user_agent
from bs4 import BeautifulSoup





def get_ip_info(url):
 return  urlparse(url).netloc


def get_server_info(url):
    try:
        response = requests.get(url, timeout=5)
        server_info = response.headers.get("Server")
        print(server_info)
        return server_info
    
    except requests.exceptions.Timeout as t:
        print(f"Timeout {t}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None


def get_os_info(url):
    host = get_ip_info(url)
    print(f"Scanning {urlparse(url).netloc} with nmap for OS detection...")
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments="-sT -O --osscan-guess --fuzzy --max-retries=2")
    if host in nm.all_hosts() and 'osmatch' in nm[host]:
        for os_info in nm[host]["osmatch"]:
            os_name = os_info['name']
            print(f"OS Name: {os_name}")
            print("Class Details:")
            for osclass in os_info.get("osclass", []):
                print(f"  - Vendor: {osclass['vendor']}")
                print(f"  - OS Family: {osclass['osfamily']}")
                print(f"  - OS Generation: {osclass['osgen']}")
                print(f"  - Accuracy: {osclass['accuracy']}%")
    else:
        print("Couldn't get OS info")

    r = get_query(url, "" ,get_random_user_agent())
    headers = r.headers
    powered_by_info = headers.get("X-Powered-By", "").lower()

    windows_servers = {"microsoft", "iis", "asp.net", ".net"}
    linux_servers = {"unix", "slackware", "debian", "suse", "mandrake", "gentoo", "arch", "fedora", "ubuntu", "centos",
                     "opensuse", "mint", "manjaro", "kali", "parrot", "alma"}

    for os_name in linux_servers:
        if os_name in powered_by_info:
            print(f"{os_name} Linux")

    for os_name in windows_servers:
        if os_name in powered_by_info:
            print("Windows")


def get_tech_stack(url):
    builtwith_url = "https://builtwith.com/?" + url
    try:
        response = requests.get(builtwith_url)
    except requests.RequestException as e:
        print(f"[!]Error: {e}")
        return None
    soup = BeautifulSoup(response.text, "html.parser")
    print(f"[*] Attempting to detect web technologies used by {url}")
    data_dict = {}
    divs = soup.find_all("div", class_="card mt-4 mb-2")
    for div in divs:
        h6 = div.find("h6", class_="card-title text-secondary")
        if h6:
            title_text = h6.get_text(strip=True)
            if title_text in ["Web Servers", "Operating Systems and Servers"]:
                img_tags = div.find_all("img")
                alt_texts = [img.get("alt", "No alt text") for img in img_tags]
                data_dict[title_text] = alt_texts
    if not data_dict:
        print(f"[-] Failed to detect web technologies on {url}")
    else:
        print(f"[+] Detected technologies: {data_dict}")
    return data_dict

