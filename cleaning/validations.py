import re
import pandas as pd
from datetime import datetime

def validate_email(df, column):
    # Added explicit \. before TLD to ensure domain has a proper dot-separated extension
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    failed_indices = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        value = str(value).strip()

        if not re.match(pattern, value):
            failed_indices.append(idx)
            detailed_errors.append({
                "rule": "validate_email",
                "column": column,
                "row_index": idx,
                "message": f"Invalid email format: {value}",
            })

    failed_df = df.loc[failed_indices]

    return failed_df, detailed_errors


def validate_email_domain(df, column):
    # Added pd.isna guard to avoid converting NaN to string "nan"
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        value = str(value).strip()
        if "@" in value:
            domain = value.split("@")[-1]
            if "." not in domain:
                failed_rows.append(idx)
                detailed_errors.append({
                    "rule": "validate_email_domain",
                    "column": column,
                    "row_index": idx,
                    "message": f"Invalid domain: {domain}"
                })

    return df.loc[failed_rows], detailed_errors


def validate_phone(df, column):
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        value_str = str(value).strip()

        # Only allow + at the very start (country code prefix), then strip it before digit check
        if value_str.startswith("+"):
            cleaned = re.sub(r"[\s\-\(\)]", "", value_str[1:])
        else:
            cleaned = re.sub(r"[\s\+\-\(\)]", "", value_str)

        if not re.match(r"^\d{7,15}$", cleaned):
            failed_rows.append(idx)
            detailed_errors.append({
                "rule": "validate_phone",
                "column": column,
                "row_index": idx,
                "message": f"Invalid phone: {value}"
            })

    return df.loc[failed_rows], detailed_errors


def validate_url(df, column):
    pattern = r"^(https?://)?(www\.)?[A-Za-z0-9\-]+\.[A-Za-z]{2,}(\S*)?$"
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        if not re.match(pattern, str(value).strip()):
            failed_rows.append(idx)
            detailed_errors.append({
                "rule": "validate_url",
                "column": column,
                "row_index": idx,
                "message": f"Invalid URL: {value}"
            })

    return df.loc[failed_rows], detailed_errors


def validate_numeric(df, column):
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        try:
            # Expanded to cover more common currency symbols and formatting characters
            cleaned = re.sub(r"[₹$€£¥%,\s]", "", str(value))
            float(cleaned)
        except:
            failed_rows.append(idx)
            detailed_errors.append({
                "rule": "validate_numeric",
                "column": column,
                "row_index": idx,
                "message": f"Not numeric: {value}"
            })

    return df.loc[failed_rows], detailed_errors


def validate_numeric_range(df, column, min_val=None, max_val=None):
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        try:
            num = float(value)
            if (min_val is not None and num < min_val) or (max_val is not None and num > max_val):
                failed_rows.append(idx)
                detailed_errors.append({
                    "rule": "validate_numeric_range",
                    "column": column,
                    "row_index": idx,
                    "message": f"Out of range: {value}"
                })
        except:
            continue

    return df.loc[failed_rows], detailed_errors


def validate_date(df, column):
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value):
            continue

        try:
            pd.to_datetime(value, errors="raise")
        except:
            failed_rows.append(idx)
            detailed_errors.append({
                "rule": "validate_date",
                "column": column,
                "row_index": idx,
                "message": f"Invalid date: {value}"
            })

    return df.loc[failed_rows], detailed_errors


def validate_not_empty(df, column):
    # Added pd.isna check so actual null/NaN values are also caught
    failed_rows = []
    detailed_errors = []

    for idx, value in df[column].items():
        if pd.isna(value) or str(value).strip() == "":
            failed_rows.append(idx)
            detailed_errors.append({
                "rule": "validate_not_empty",
                "column": column,
                "row_index": idx,
                "message": "Empty value"
            })

    return df.loc[failed_rows], detailed_errors


def duplicate_identifier(df, column):
    failed_rows = []
    errors = []

    # keep=False flags all occurrences — safest choice since we can't know which is correct
    duplicates = df[df.duplicated(subset=[column], keep=False)]

    for idx, row in duplicates.iterrows():
        failed_rows.append(idx)

        errors.append({
            "rule": "duplicate_identifier",
            "column": column,
            "row_index": idx,
            "message": f"Repeated identifier in column '{column}'"
        })

    failed_df = df.loc[failed_rows].copy()

    return failed_df, errors

