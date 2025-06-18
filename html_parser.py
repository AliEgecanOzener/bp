import requests
from bs4 import BeautifulSoup
from termcolor import colored
def parse_element(element):
    if element.name == "input":
       return input_element_parse(element)
    elif element.name == "select":
       return select_element_parse(element)
    elif element.name == "textarea":
        return textarea_element_parse(element)
    else:
        return None

def input_element_parse(input_element):
    input_parameters = {
        "type": input_element.get('type'),
        "name": input_element.get('name'),
        "value": input_element.get('value'),
        "maxlength": input_element.get('maxlength'),
        "accept": input_element.get('accept'),
        "required": input_element.get("required"),
        "autocomplete": input_element.get("autocomplete"),
        "pattern": input_element.get('pattern')
    }
    return input_parameters

def select_element_parse(select_element):
    select_parameters = {
        "type": 'select',
        "name": select_element.get('name'),
        "id": select_element.get('id'),
        "options": []
    }

    for option in select_element.findAll('option'):
        option_parameters = {
            "value": option.get('value')
        }
        select_parameters['options'].append(option_parameters)
    return select_parameters

def textarea_element_parse(textarea_element):
    return {
        "type": "textarea",
        "name": textarea_element.get("name"),
        "maxlength": textarea_element.get("maxlength"),
        "required": textarea_element.get("required"),
        "autocomplete": textarea_element.get("autocomplete")
    }

def form_parse(html_content):
    if not html_content or not isinstance(html_content, str):
        return []

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
    except Exception as e:
        print(colored(f"[!] Error while analyzing: {e}","yellow"))
        return []

    all_form_list = []
    forms = soup.find_all('form')

    if not forms:
        return all_form_list

    for form in forms:
        form_dict = {
            "method": form.get('method'),
            "action": form.get('action'),
            "enctype": form.get('enctype'),
            "elements": []
        }
        for element in form.find_all(['input', 'select', 'textarea']):
            attributes = parse_element(element)
            if attributes:
                form_dict['elements'].append(attributes)

        all_form_list.append(form_dict)


    return all_form_list
