from urllib.parse import urlparse, parse_qs
from utils import get_query
from bs4 import BeautifulSoup


def analyze_form_fields(cookie, header):
    url = input("URL: ")
    response = get_query(url, cookie, header)
    if response:
       soup = BeautifulSoup(response.text, 'html.parser')
       soup = soup.prettify()
       form_start = "<form>"
       form_end = "</form>"
       soup = form_start + soup.split(form_start)[0]
       soup = soup.split(form_end)[-1] + form_end
       print(soup)


def user_parameter_extract(string):
    user_parameter_set = set()
    if string != '':
        for parameter in string.split(','):
            parameter = parameter.strip()
            user_parameter_set.add(parameter)
        return user_parameter_set
    else:
        return None

def parsed_post_data(data):
    parsed_data = {data_value.split('=')[0].strip(): data_value.split('=')[1].strip() for data_value in data.split('&')}
    return parsed_data


def valid_user_params(url, user_parameters_set):
    url_parameters = set(parse_qs(urlparse(url).query).keys())
    matched = url_parameters & user_parameters_set
    return matched

def is_user_get_parameter_valid(url, user_parameters_string):
 url_parameters = set(parse_qs(urlparse(url).query).keys())
 user_parameters_set= set(user_parameters_string.strip().split(","))
 matched = url_parameters & user_parameters_set
 return matched if matched else None

def post_data_extract(post_data):
    if not post_data:
        return None
    data = {}
    for post_parameter in post_data.strip().split('&'):
        parts = post_parameter.split('=', 1)
        key = parts[0]
        value = parts[1] if len(parts) > 1 else ''
        data[key] = value
    return data


def user_parameter_vs_post_data(extracted_post_data, user_parameters):
 matched_parameters = set()
 for data in extracted_post_data:
  for parameter in user_parameters:
   if data == parameter:
    matched_parameters.add(data)
 return matched_parameters


def compare_matched_params_with_forms(form_list, matched_parameters):
    attack_parameters = []
    if matched_parameters:
        for form in form_list:
            for element in form['elements']:
                for parameter in matched_parameters:
                    if element.get('name'):
                        if element.get('type') not in ['button', 'submit']:
                            if element['name'] == parameter:
                                   attack_parameters.append(parameter)
    return attack_parameters


