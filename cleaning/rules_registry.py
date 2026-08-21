from .validations import *
from .cleaning_rules import *
from .deduplication import drop_duplicates

RULES_REGISTRY = {
    #validations
    "validate_email": {"label":"Validate Email","function" : validate_email, "type": "validation", "allowed_types": ["email"]},
    "validate_email_domain": {"label":"Validate Email Domain","function": validate_email_domain, "type":"validation", "allowed_types": ["email"]},
    "validate_phone": {"label":"Validate Phone","function": validate_phone, "type":"validation", "allowed_types": ["phone"]},
    "validate_url": {"label":"Validate URL", "function": validate_url, "type":"validation", "allowed_types": ["url"]},
    "validate_numeric":{"label":"Validate Number Format", "function": validate_numeric, "type":"validation", "allowed_types": ["numeric"]},
    "validate_numeric_range":{"label":"Validate Numeric Range", "function": validate_numeric_range, "type":"validation", "allowed_types": ["numeric",]},
    "validate_date": {"label":"Validate Date", "function": validate_date, "type":"validation", "allowed_types": ["date",]},
    "validate_not_empty": {"label":"Not Empty Check", "function": validate_not_empty, "type":"validation", "allowed_types": ["email", "phone", "url", "numeric", "date", "text"]},


    #cleaning
    "trim_whitespace": {"label":"Whitespace Check", "function": trim_whitespace, "type":"cleaning", "allowed_types": ["email", "phone", "url", "numeric", "date", "text"]},
    "clean_special_chars": {"label":"Remove Special Characters", "function": clean_special_chars, "type":"cleaning", "allowed_types": ["email", "phone","url", "numeric","date", "text"]},
    "handle_missing": {"label":"Handle Missing Values","function": handle_missing, "type":"cleaning","allowed_types":["email","phone","url","numeric","date","text"],"strategies":["flag","median","mean","placeholder","drop"]},
    "normalize_currency":{"label":"Normalize Currency / Number Format", "function":normalize_currency, "type":"cleaning","allowed_types":["numeric"]},
    "lowercase_email": {"label": "Lowercase Email Normalization", "function": lowercase_email, "type": "cleaning", "allowed_types": ["email"]},
    "title_case_text": {"label": "Convert Text to Title Case", "function": title_case_text, "type": "cleaning", "allowed_types": ["text"]},
    "normalize_url_protocol": {"label": "Prepend https:// Protocol", "function": normalize_url_protocol, "type": "cleaning", "allowed_types": ["url"]},
    "remove_non_alphanumeric": {"label": "Remove Non-Alphanumeric Characters", "function": remove_non_alphanumeric, "type": "cleaning", "allowed_types": ["text"]},
    "remove_phone_91_prefix": {"label": "Remove +91 or 91 Prefix", "function": remove_phone_91_prefix, "type": "cleaning", "allowed_types": ["phone"]},
    "format_phone_number": {"label": "Standardize Phone Format", "function": format_phone_number, "type": "cleaning", "allowed_types": ["phone"]},

    # Predefined rules (expanded dynamically in engine.py)
    "predefined_email": {"label": "Predefined Email Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["email"]},
    "predefined_phone": {"label": "Predefined Phone Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["phone"]},
    "predefined_numeric": {"label": "Predefined Numeric Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["numeric"]},
    "predefined_text": {"label": "Predefined Text Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["text"]},
    "predefined_url": {"label": "Predefined URL Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["url"]},
    "predefined_date": {"label": "Predefined Date Rule", "function": lambda df, col, col_t=None: (df, []), "type": "cleaning", "allowed_types": ["date"]},

    #dedupe
    "drop_duplicates": {"label":"Remove Duplicates", "function": drop_duplicates, "type": "dedupe", "allowed_types": ["email", "phone", "url", "numeric", "date", "text"]},

    #dup identifier
    "duplicate_identifier": {"label": "Check duplicates", "function": duplicate_identifier, "type":"validation", "allowed_types":["identifier"] }
}