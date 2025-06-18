import re
import tempfile
import time
import html
import webbrowser
from utils import (get_query, post_query, get_random_user_agent, generate_random_string, parse_comma, double_url_encode,parse_headers,
                   dict_to_string, http_basic_auth)
from termcolor import colored
from html_parser import form_parse
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, parse_qs, quote, urlencode


arguments = None

def xss_scanning(args):
    global arguments
    arguments = args
    url = args.url
    cookie = args.cookie or ""
    headers = args.headers
    data = parse_data_arg(args.data) if args.data else None
    method = parse_comma(args.m)
    parameters = parse_comma(args.p)
    forms = parse_forms(url, cookie)
    stored_urls = parse_comma(args.stored_urls)
    stored_urls = [u.lower() for u in stored_urls] if stored_urls else []
    method = [m.lower() for m in method] if method else None


    xss_types = []
    if args.stored:
        xss_types.append("stored")

    if args.reflected:
        xss_types.append("reflected")

    if not xss_types:
        xss_types = ["reflected", "stored"]

    if not method and not data and not parameters:
        parameter_based_scan(url, cookie, "", forms, stored_urls=stored_urls, types=xss_types)
        blind_header_injection(url, cookie, xss_types, stored_urls)

    elif not method and not data and parameters:
        parameter_based_scan(url, cookie, parameters, forms, stored_urls=stored_urls, types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)

    elif not method and data and not parameters:
        handle_form_scan(url, cookie, forms, parameters, data=data, stored_urls=stored_urls, types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)

    elif not method and data and parameters:
        parameter_based_scan(url, cookie, parameters, forms, stored_urls=stored_urls, types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)

    elif method and not data and not parameters:
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)
        else:
            header_injection(url, cookie, headers, stored_urls, xss_types)
            blind_header_injection(url, cookie, xss_types, stored_urls)
            handle_form_scan(url, cookie, forms, parameters, data=data, methods=method, stored_urls=stored_urls,
                             types=xss_types)

    elif method and not data and parameters:
        parameter_based_scan(url, cookie, parameters, forms, stored_urls=stored_urls, types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)

    elif method and data and not parameters:
        handle_form_scan(url, cookie, forms, parameters, data=data, methods=method, stored_urls=stored_urls,
                         types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)

    elif method and data and parameters:
        parameter_based_scan(url, cookie, parameters, forms, stored_urls=stored_urls, types=xss_types)
        if headers:
            header_injection(url, cookie, headers, stored_urls, xss_types)
        elif args.headers_all:
            blind_header_injection(url, cookie, xss_types, stored_urls)




def parameter_based_scan(url, cookie, parameters=None, forms=None, stored_urls=None, types=None):

    if forms is None and ("reflected" in types or "stored" in types):
        forms = parse_forms(url, cookie)

    if "reflected" in types or "stored" in types:
        if not forms:
            print(colored("[!] No forms found.\n", "yellow"))
            return

        parsed_url = urlparse(url)
        url_params = list(parse_qs(parsed_url.query).keys())
        form_params = {
            name
            for _, _, inputs in forms
            for name in inputs
            if name
        }

        if not parameters:
            parameters = set(url_params) | form_params
            if not parameters:
                print(colored("[!] No parameters found in URL or forms to test.\n", "yellow"))
                return
            else:
                print(colored(f"[!] No parameters provided. Extracted parameters: {parameters}\n", "yellow"))
        else:
            parameters = set(parameters)

        handle_form_scan(url, cookie, forms, parameters, stored_urls=stored_urls, types=types)


def handle_form_scan(url, cookie, forms, parameters=None, data=None, methods=None, stored_urls=None, types=None, driver=None):

    if not types:
        types = ["reflected", "stored"]

    for form in forms:
        if not isinstance(form, tuple) or len(form) != 3:
            continue
        method, action_url, form_inputs = form


        if methods and method not in methods:
            print(colored(f"[*] This form does not contain a {method.upper()} method", "yellow"))
            continue

        if not form_inputs:
            print(colored("[-] No usable input fields found in this form.\n", "red"))
            continue

        intersect_params = determine_test_parameters(form_inputs, parameters, data)
        if not intersect_params:
            continue

        print_form_info(method, url, form_inputs)
        print(colored(f"[+] Parameters to test: {intersect_params}\n", "cyan"))

        for test_param in intersect_params:
            if form_inputs[test_param]['type'] in ['submit', 'button', 'reset']:
                continue

            randomstr = generate_random_string(5)
            test_data = build_test_data(form_inputs, test_param, randomstr, data)
            print(colored("-" * 120, "cyan"))

            headers = {"User-Agent": get_random_user_agent()}
            response, built_url, post_data = None, None, None

            if method == "get":
                parsed_action = urlparse(action_url)
                original_query = parse_qs(parsed_action.query)
                flat_query = {k: v[0] for k, v in original_query.items()}
                merged_query = {**flat_query, **test_data}
                new_query = urlencode(merged_query)
                built_url = parsed_action._replace(query=new_query).geturl()

                print(f"[*] Testing GET param '{test_param}' at URL: {built_url}\n")
                response = get_query(built_url, cookie, headers)

            elif method == "post":
                built_url = action_url
                encoded_data = {
                    k: v.strip().replace(" ", "+") if isinstance(v, str) else "+"
                    for k, v in test_data.items()
                }
                print(f"[*] Testing POST param '{test_param}' at URL: {built_url}\n")
                response = post_query(built_url, cookie, headers, encoded_data, "")
                post_data = encoded_data

            else:
                print("Unsupported HTTP method. Skipping...\n")
                continue

            reflected, rcontexts = check_reflected_xss(response, url, randomstr, cookie, headers, test_param, types)
            if reflected:
                print(colored(f"[*] {test_param} might be vulnerable to reflected XSS"))

            stored, scontexts = check_stored_xss(stored_urls, built_url, action_url, method, cookie, headers, randomstr, types)
            if stored:
                print(colored("[*] Checking payload for potential stored XSS...\n", "yellow"))

            if stored or reflected:
                scan_config = {
                    'url': url,'cookie': cookie,'headers': headers,'method': method,'randomstr': randomstr,'rcontexts': rcontexts,
                    'scontexts': scontexts,'form': form,'test_param': test_param,
                }

                if method == "post":
                    scan_config['post_data'] = post_data
                    scan_config['action_url'] = action_url
                else:
                    scan_config['built_url'] = built_url

                if stored:
                    scan_config['stored'] = stored
                    scan_config['stored_urls'] = stored_urls
                if reflected:
                    scan_config['reflected'] = reflected

                if "reflected" in types or "stored" in types:
                    injection(scan_config)




def determine_test_parameters(form_inputs, parameters, data):
    if data:
        intersect_fields = set(data.keys()) & set(form_inputs.keys())
        return set(parameters) & intersect_fields if parameters else intersect_fields
    elif parameters:
        return set(parameters) & set(form_inputs)
    else:
        return {
            name for name, attr in form_inputs.items()
            if attr['type'] not in ['submit', 'button', 'reset']
        }


def build_test_data(form_inputs, test_param, randomstr, data):
    test_data = {}
    for name, attr in form_inputs.items():
        if attr['type'] in ['submit', 'button', 'reset']:
            test_data[name] = attr['value']
        else:
            value = data[name] if data and name in data else attr['value'] or "test"
            test_data[name] = randomstr if name == test_param else value
    return test_data

def print_form_info(method, url, form_inputs):
    print(colored(f"[+] {method.upper()} method form found on {url}.", "yellow"))
    print(colored("[+] Detected form parameters:", "yellow"))
    for name in form_inputs:
        print(colored(f"    {name}", "yellow"))
    print()

def check_reflected_xss(response, url, randomstr, cookie, headers, test_param=None, types=None):
    if types and "reflected" not in types:
        return False, None

    if not response or not randomstr:
        return False, None

    if randomstr in response.text:
        baseline_resp = get_query(url, cookie, headers)
        if baseline_resp and randomstr not in baseline_resp.text:
            contexts = detect_contexts(response.text, randomstr)
            print(colored(f"[!] Value reflected on {url}", "green"))
            print(f"[*] Contexts: {contexts}\n")
            return True, contexts
        else:
            print(colored("[-] Payload also appeared in normal page, likely a false positive.\n", "red"))
    else:
        if test_param:
            print(colored(f"[-] No reflected XSS for '{test_param}'\n", "red"))
        else:
            print(colored("[-] No reflected XSS detected.\n", "red"))
    return False, None


def check_stored_xss(stored_urls, verify_base_url, action_url, method, cookie, headers, randomstr, types=None):
    if types and "stored" not in types:
        return False, None

    check_urls = stored_urls if stored_urls else [action_url]
    for verify_url in check_urls:
        full_url = urljoin(verify_base_url, verify_url)
        time.sleep(1)
        verify_resp = get_query(full_url, cookie, headers)

        if verify_resp and randomstr in verify_resp.text:
            contexts = detect_contexts(verify_resp.text, randomstr)
            print(colored(f"[+] String stored at {full_url}", "green"))
            print(colored(f"    Contexts: {contexts}\n", "cyan"))
            return True, contexts
        else:
            print(colored(f"[-] Payload not stored on: {full_url}\n", "red"))
    return False, None

def open_response_in_browser(response_text):
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html', encoding='utf-8') as f:
        f.write(response_text)
        temp_path = f.name
    webbrowser.open('file://' + temp_path)


def detect_contexts(response_text, random_str):
    soup = BeautifulSoup(response_text, "html.parser")

    found_contexts = {
        "html_context": [],
        "attribute_context": [],
        "event_handler_context": [],
        "js_context": [],
        "css_context": [],
        "comment_context": [],
        "unknown_context": []
    }

    detected_any = set()

    def add_context(context_category, tag=None, attribute_name=None):
        context_info = {
            "example": None,
            "tag": tag.name if tag else None,
            "attr": attribute_name
        }
        key = (context_category, tag.name if tag else None, attribute_name)
        if key not in detected_any:
            found_contexts[context_category].append(context_info)
            detected_any.add(key)
            print(f"[+] {context_category.replace('_', ' ').title()} (tag: {context_info['tag']}, attr: {context_info['attr']})")

    for tag in soup.find_all():
        if tag.name not in ["script", "style", "noscript"]:
            text = tag.get_text()
            if random_str in text:
                add_context("html_context", tag)

    js_keywords = ["alert", "eval", "console", "prompt", "confirm", "setTimeout", "setInterval", "location", "document"]
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            val_str = " ".join(val) if isinstance(val, list) else str(val)

            if random_str in val_str:
                attr_lower = attr.lower()

                if attr_lower.startswith("on"):
                    add_context("event_handler_context", tag, attr)
                elif attr_lower == "style":
                    add_context("css_context", tag, attr)
                elif val_str.strip().lower().startswith("javascript:") or any(js_kw in val_str for js_kw in js_keywords):
                    add_context("js_context", tag, attr)
                else:
                    add_context("attribute_context", tag, attr)

    for script in soup.find_all("script"):
        if script.string and random_str in script.string:
            add_context("js_context", script)

    for style in soup.find_all("style"):
        if style.string and random_str in style.string:
            add_context("css_context", style)

    for element in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment_text = str(element)
        if random_str in comment_text:
            add_context("comment_context")

    if not detected_any and random_str in response_text:
        add_context("unknown_context")

    return found_contexts


def parse_data_arg(raw):
    data = {}
    if raw:
        for pair in raw.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                data[key.strip()] = value.strip()
    return data

def parse_forms(url, cookie):
    headers = {
        "User-Agent": get_random_user_agent()
    }
    html = get_query(url, cookie, headers)

    if not html:
        print(colored(f"[*] Couldn't receive response from {url}", "light_red"))
        return []

    html_text = html.text
    forms = form_parse(html_text)

    parsed_forms = []

    parsed_url = urlparse(url)
    url_params = parse_qs(parsed_url.query)
    url_param_names = set(url_params.keys())


    all_form_input_names = set()
    for form in forms:
        if not form or not isinstance(form, dict):
            continue

        method = (form.get('method') or 'get').lower()
        action = form.get('action') or url
        action_url = urljoin(url, action) if not action.startswith("http") else action

        elements = form.get('elements', [])
        form_inputs = {
            el.get('name'): {
                'type': (el.get('type') or 'text').lower(),
                'value': el.get('value') if el.get('value') is not None else ''
            }
            for el in elements if isinstance(el, dict) and el.get('name')
        }

        all_form_input_names.update(form_inputs.keys())
        parsed_forms.append((method, action_url, form_inputs))

    orphan_params = url_param_names - all_form_input_names
    if orphan_params:
        extra_inputs = {
            param: {
                'type': 'text',
                'value': url_params[param][0] if url_params[param] else ''
            }
            for param in orphan_params
        }
        parsed_forms.append(('get', url, extra_inputs))

    return parsed_forms


def injection(scan_config):
    if scan_config.get('rcontexts'):
        scan_config["reflected"] = True
        scan_config["stored"] = False
        type_based_context(scan_config, scan_config['rcontexts'])

    if scan_config.get('scontexts'):
        scan_config["reflected"] = False
        scan_config["stored"] = True
        type_based_context(scan_config, scan_config['scontexts'])

def type_based_context(scan_config, contexts):
    for context_type, context_list in contexts.items():
        if not context_list:
            continue
        payloads = load_payloads(context_type)
        if not payloads:
            continue

        for raw_payload in payloads:
            if scan_config.get("force_encoding"):
                for enc_type in scan_config.get("force_encoding_types", ["url"]):
                    if enc_type == "url":
                        payload = quote(raw_payload)
                    elif enc_type == "double_url":
                        payload = quote(quote(raw_payload))
                    elif enc_type == "html":
                        payload = html.escape(raw_payload)
                    else:
                        payload = raw_payload

                    if scan_config.get('method') == "get":
                        perform_get(scan_config, payload, raw_payload)
                    elif scan_config.get('method') == "post":
                        perform_post(scan_config, payload, raw_payload)
            else:
                payload = raw_payload
                if scan_config.get('method') == "get":
                    perform_get(scan_config, payload, raw_payload)
                elif scan_config.get('method') == "post":
                    perform_post(scan_config, payload, raw_payload)


def load_payloads(context_type):
    def get_payload_file(xss_type):
        file_map = {
            "html_context": "xss_payloads/raw_html_context.txt",
            "attribute_context": "xss_payloads/raw_attribute_context.txt",
            "event_handler_context": "xss_payloads/raw_event_handler_context.txt",
            "comment_context": "xss_payloads/raw_comment_context.txt",
            "js_context": "xss_payloads/raw_js_context.txt",
            "css_context": "xss_payloads/raw_css_context.txt",
        }
        print("\n")
        print("*" * 120)
        print(colored(f"[*] Reading from payload file: {file_map.get(xss_type.lower())}","cyan"))
        print("*" * 120)
        print("\n")
        time.sleep(1.5)
        return file_map.get(xss_type.lower())

    payload_file = get_payload_file(context_type)
    if not payload_file:
        print(f"[-] Filename could not fount. (context_type={context_type})")
        return None
    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[-] Payload file could not be read: {payload_file} - {e}")
        return None

def perform_get(scan_config, payload, raw_payload):
    built_url = scan_config.get('built_url')
    randomstr = scan_config.get('randomstr')
    if not scan_config.get('test_header'):
        headers = {"User-Agent": get_random_user_agent()}
    else:
        headers = scan_config.get('headers')

    if built_url and randomstr in built_url:
        test_url = built_url.replace(randomstr, payload)
        print("*" * 120)
        print(colored(f"\n[*] GET request to: {test_url}", "green"))
        response = get_query(test_url, scan_config.get('cookie'), headers)
        print(colored(f"[*] Request Headers: {dict_to_string(response.request.headers)}", "light_yellow"))
        check_payload_status(scan_config, response, payload, raw_payload, test_url)

    if scan_config.get('test_header'):
        for key, value in headers.items():
            if randomstr in value:
                headers[key] = value.replace(randomstr, payload)
                print("*" * 120)
                print(colored(f"\n[*] GET request to: {built_url}", "green"))
                response = get_query(built_url, scan_config.get('cookie'), headers)
                print(colored(f"[*] Request Headers: {dict_to_string(response.request.headers)}", "light_yellow"))
                check_payload_status(scan_config, response, payload, raw_payload, built_url)
                headers[key] = value.replace(payload, randomstr)

def perform_post(scan_config, payload, raw_payload):
    headers = {"User-Agent": get_random_user_agent()}
    encoded_data = {
        k: (v.strip().replace(" ", "+") if isinstance(v, str) else "+")
        for k, v in scan_config.get('post_data', {}).items()
    }
    for key, value in encoded_data.items():
        if scan_config['randomstr'] in value:
            encoded_data[key] = value.replace(scan_config['randomstr'], payload)
    print("*" * 120)
    print(colored(f"\n[*] POST request to: {scan_config['url']}", "green"))
    print(colored(f"[*] POST Data: {dict_to_string(encoded_data)}", "light_yellow"))

    response = post_query(scan_config['url'], scan_config['cookie'], headers, encoded_data, "")
    print(colored(f"[*] Request Headers: {dict_to_string(response.request.headers)}", "light_yellow"))
    check_payload_status(scan_config, response, payload, raw_payload, scan_config['url'])

def check_payload_status(scan_config, response, payload, raw_payload, url):
    cookie = scan_config['cookie']
    headers = scan_config['headers']

    if scan_config.get('stored'):
        urls = scan_config.get('stored_urls') or [url]
        for su in urls:
            base_response = get_query(su, cookie, headers)
            analyze_encoding(payload, raw_payload, base_response.text, "stored", scan_config, su)

    if scan_config.get('reflected'):
        analyze_encoding(payload, raw_payload, response.text, "reflected", scan_config, url)

def extract_context_fragment(payload, response_text, context_window=100):
    pattern = re.escape(payload)
    match = re.search(r'.{0,%d}%s.{0,%d}' % (context_window, pattern, context_window), response_text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(0)
    return None

def is_false_positive(payload, context_fragment):
    context_fragment = context_fragment.lower()

    if any(tag in context_fragment for tag in ["<textarea", "<title", "<xmp", "<pre", "<code", "<noscript"]):
        if any(close in payload.lower() for close in ["</", "<script", "<img", "onerror", "onload"]):
            return False
        return True
    return False

def analyze_encoding(payload, raw_payload, response_text, xss_type, scan_config, url):
    method = scan_config.get('method')
    encodings_found = []
    html_escaped = html.escape(payload)
    url_encoded = quote(payload)
    double_url_encoded = double_url_encode(payload)
    js_escaped = payload.replace("'", "\\'").replace('"', '\\"').replace("<", "\\<").replace(">", "\\>")

    if html_escaped in response_text:
        encodings_found.append("HTML Escape")
    if url_encoded in response_text:
        encodings_found.append("URL Encode")
    if js_escaped in response_text:
        encodings_found.append("JS Escape")

    if any(enc in encodings_found for enc in ["HTML Escape", "URL Encode", "JS Escape"]):
        if raw_payload == payload:
            for enc in encodings_found:
                print(colored(f"[!] This page takes precautions with {enc} ", "yellow"))
            scan_config["force_encoding"] = True
            scan_config["force_encoding_types"] = ["url", "double_url"]

            def check_encoded(payload_to_test):
                if method == "get":
                    print(colored(f"[*] Trying encoded payload: {payload_to_test}", "yellow"))
                    perform_get(scan_config, payload_to_test, raw_payload)
                elif method == "post":
                    print(colored(f"[*] Trying encoded payload: {payload_to_test}", "yellow"))
                    perform_post(scan_config, payload_to_test, raw_payload)

            check_encoded(url_encoded)
            check_encoded(double_url_encoded)

    else:

        if raw_payload in response_text:
            encodings_found.append("Original")
            fragment = extract_context_fragment(payload, response_text)
            if fragment and is_false_positive(payload, fragment):
                print(colored(f"[!] Payload found in likely non-executable context: possible false positive.", "yellow"))
            else:
                print(colored(f"[+] Payload found in response for {xss_type} context. Likely successful.", "light_green"))
                if arguments.open_browser:
                    if method == "post":
                        open_response_in_browser(response_text)
                    if method == "get":
                        if scan_config.get('test_header'):
                            open_response_in_browser(response_text)
                        else:
                            webbrowser.open(url)

        if raw_payload not in response_text:
            if raw_payload != payload:
                print(colored(f"[-] Injection was not successful.","red"))
                return

    if encodings_found == ["Original"]:
        triggers = [
            "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmousemove", "onmouseout",
            "onmouseenter", "onmouseleave", "oncontextmenu", "onkeydown", "onkeypress", "onkeyup",
            "onfocus", "onblur", "onchange", "oninput", "oninvalid", "onreset", "onselect", "onsubmit",
            "onload", "onunload", "onresize", "onscroll", "onbeforeunload", "onerror", "oncopy", "oncut", "onpaste",
            "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "onabort",
            "oncanplay", "oncanplaythrough", "ondurationchange", "onemptied", "onended", "onloadeddata",
            "onloadedmetadata",
            "onloadstart", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onseeked", "onseeking",
            "onstalled",
            "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "onanimationstart", "onanimationend",
            "onanimationiteration",
            "ontransitionend", "onpointerdown", "onpointerup", "onpointermove", "onpointerover", "onpointerout",
            "onshow", "ontoggle",
            "onpointerenter", "onpointerleave", "ongotpointercapture", "onlostpointercapture", "onwheel",
            "onspellcheck", "formaction"
        ]
        for trigger in triggers:
            if trigger in payload.lower():
                print(colored(f"[!] Please trigger the {trigger} for XSS.", "yellow"))
                break
    return None

#-------------------------------------------------------HTTP Header Injection------------------------------------------------------------------
def header_injection(url, cookie, headers, stored_urls, types):
    if not headers:
        blind_header_injection(url, cookie, types, stored_urls)
        return
    if not types:
        types = ["reflected", "stored"]

    parsed_headers = parse_headers(headers)
    randomstr = generate_random_string(5)

    for key, value in parsed_headers.items():
        if "TARGET" not in value:
            print(colored(f"[!] No 'TARGET' found in header '{key}', entire value will be replaced.", "yellow"))
            value = "TARGET"
        changed_value = value.replace("TARGET", randomstr)

        temp_headers = parsed_headers.copy()
        temp_headers[key] = changed_value

        print(colored(f"[*] Testing header : {key} with changed random value: {changed_value}", "cyan"))
        response = get_query(url, cookie, temp_headers)

        reflected, rcontexts = False, []
        stored, scontexts = False, []

        if "reflected" in types:
            print(colored(f"[*] Checking header {key} for potential reflected XSS...\n", "yellow"))
            reflected, rcontexts = check_reflected_xss(response, url, randomstr, cookie, "", key, types)

        if "stored" in types:
            print(colored(f"[*] Checking header {key} for potential stored XSS...\n", "yellow"))
            stored, scontexts = check_stored_xss(stored_urls, url, url, "get", cookie, "", randomstr, types)

        if stored or reflected:
            scan_config = {'built_url': url, 'cookie': cookie, 'headers': temp_headers, 'method': "get", 'randomstr': randomstr, 'test_param': key,
                           'rcontexts': rcontexts, 'scontexts': scontexts, 'stored': stored, 'reflected': reflected, "test_header": True
            }

            if stored:
                scan_config['stored_urls'] = stored_urls

            injection(scan_config)

def blind_header_injection(url, cookie, types, stored_urls):
    common_headers = [
        "User-Agent", "Referer", "X-Forwarded-For", "Origin", "Cookie", "Authorization",
        "X-Requested-With", "Accept-Language", "Accept-Encoding", "X-Custom-Header",
        "Accept", "Accept-Charset", "Cache-Control", "Connection", "Content-Length",
        "Content-Type", "Date", "DNT", "Expect", "Forwarded", "From", "Host",
        "If-Match", "If-Modified-Since", "If-None-Match", "If-Range",
        "If-Unmodified-Since", "Max-Forwards", "Pragma", "Proxy-Authorization",
        "Range", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning",
        "X-Forwarded-Host", "X-Forwarded-Proto", "X-Frame-Options", "X-XSS-Protection",
        "X-Content-Type-Options", "X-Powered-By", "X-Real-IP", "X-Correlation-ID",
        "X-Api-Version","Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Headers", "Access-Control-Allow-Methods",
        "Access-Control-Expose-Headers", "Access-Control-Max-Age",
        "CF-Connecting-IP", "True-Client-IP", "X-Cluster-Client-IP",
        "X-Forwarded-Port", "X-Forwarded-Protocol", "X-Request-ID",
        "Cookie2", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
        "Sec-Fetch-User", "Upgrade-Insecure-Requests", "Content-Security-Policy",
        "Content-Security-Policy-Report-Only", "Expect-CT", "NEL", "Report-To",
        "Timing-Allow-Origin", "X-DNS-Prefetch-Control"
    ]

    for header in common_headers:
        randomstr = generate_random_string(5)
        temp_headers = {header: randomstr}

        if header.lower() != "user-agent":
            temp_headers["User-Agent"] = get_random_user_agent()

        print(colored(f"[*] Testing header: {header} with random string: {randomstr}", "yellow"))
        response = get_query(url, cookie, temp_headers)

        if not response:
            print(colored(f"[!] No response for header '{header}'.", "red"))
            continue

        reflected, rcontexts = False, []
        stored, scontexts = False, []

        if "reflected" in types:
            print(colored(f"[*] Checking header {header} for potential reflected XSS...\n", "yellow"))
            reflected, rcontexts = check_reflected_xss(response, url, randomstr, cookie, "", header, types)

        if "stored" in types:
            print(colored(f"[*] Checking header {header} for potential stored XSS...\n", "yellow"))
            stored, scontexts = check_stored_xss(stored_urls, url, url, "get", cookie, "", randomstr, types)

        if stored or reflected:
            scan_config = {'built_url': url,'cookie': cookie,'headers': temp_headers,'method': "get",'randomstr': randomstr,'test_param': header,
                           'rcontexts': rcontexts, 'scontexts': scontexts, 'stored': stored, 'reflected': reflected, "test_header": True
            }

            if stored:
                scan_config['stored_urls'] = stored_urls

            injection(scan_config)


