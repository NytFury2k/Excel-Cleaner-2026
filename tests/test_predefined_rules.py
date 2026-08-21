import pytest
import pandas as pd
from cleaning.cleaning_rules import remove_phone_91_prefix, format_phone_number
from cleaning.engine import run_cleaning_pipeline, load_predefined_rules_from_db

def test_remove_phone_91_prefix():
    df = pd.DataFrame({"phone": ["+919876543210", "919876543210", "9876543210", "+19876543210"]})
    cleaned_df, errors = remove_phone_91_prefix(df, "phone")
    assert cleaned_df["phone"][0] == "9876543210"
    assert cleaned_df["phone"][1] == "9876543210"
    assert cleaned_df["phone"][2] == "9876543210"
    assert cleaned_df["phone"][3] == "+19876543210"

def test_format_phone_number():
    df = pd.DataFrame({"phone": ["9876543210", "987-654-3210", "(987) 654-3210", "+19876543210"]})
    cleaned_df, errors = format_phone_number(df, "phone")
    assert cleaned_df["phone"][0] == "(987) 654-3210"
    assert cleaned_df["phone"][1] == "(987) 654-3210"
    assert cleaned_df["phone"][2] == "(987) 654-3210"
    assert cleaned_df["phone"][3] == "+19876543210"

def test_predefined_rules_expansion(monkeypatch):
    # Mock load_predefined_rules_from_db to return our custom mock config
    mock_config = {
        "email": {"validate_email": True, "lowercase_email": True},
        "phone": {"validate_phone": True, "remove_phone_91_prefix": True, "format_phone_number": True},
        "numeric": {"validate_numeric": True, "normalize_currency": False},
        "text": {"clean_special_chars": True, "title_case_text": True, "trim_whitespace": True},
        "url": {"validate_url": True, "normalize_url_protocol": True},
        "date": {"validate_date": True}
    }
    monkeypatch.setattr("cleaning.engine.load_predefined_rules_from_db", lambda: mock_config)

    df = pd.DataFrame({
        "email": ["  TEST@EXAMPLE.COM  "],
        "phone": ["+919876543210"],
        "url": ["example.com"]
    })

    # Let's run cleaning pipeline with predefined rules
    selected_rules = [
        ("predefined_email", "email"),
        ("predefined_phone", "phone"),
        ("predefined_url", "url")
    ]

    cleaned_df, invalid_df, removed_duplicates, detailed_errors, incompatibility_errors, summary = run_cleaning_pipeline(
        df, selected_rules, type_overrides={"email": "email", "phone": "phone", "url": "url"}
    )

    # Email: should be trimmed, lowercased, and validated
    # Phone: should have +91 removed, formatted as (XXX) XXX-XXXX, and validated
    # URL: should have https:// prepended and validated
    assert cleaned_df["email"][0] == "test@example.com"
    assert cleaned_df["phone"][0] == "(987) 654-3210"
    assert cleaned_df["url"][0] == "https://example.com"
