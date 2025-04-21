def parse_element(element):
    if element.name == "input":
       return input_element_parse(element)
    elif element.name == "select":
       return select_element_parse(element)
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

def form_parse(html_content):
    all_form_list = []
    form_count = 0
    for form in html_content.findAll('form'):
        form_count += 1
        form_dict = {
            "method": form.get('method'),
            "action": form.get('action'),
            "enctype": form.get('enctype'),
            "elements": []
        }
        for element in form.find_all(['input', 'select']):
            attributes = parse_element(element)
            if attributes:
                form_dict['elements'].append(attributes)

        all_form_list.append(form_dict)
        print(all_form_list)
    return all_form_list, form_count