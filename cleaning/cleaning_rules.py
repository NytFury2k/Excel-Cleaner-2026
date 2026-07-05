import pandas as pd
import re

def trim_whitespace(df, column, column_type):
    df[column]= df[column].astype(str).str.strip()
    return df, []


def clean_special_chars(df, column, column_type= None):

    print("clean special characters called for: ", column, "type: ", column_type)
    df = df.copy()

    def clean_value(value):
        if pd.isna(value):
            return value
        
        value= str(value)

        if column_type == "numeric":
            cleaned= re.sub(r"[^\d]", "", value)
        
        elif column_type == "phone":
            cleaned= re.sub(r"[^\d+]", "", value)
        
        elif column_type == "email":
            cleaned= re.sub(r"[^a-zA-Z0-9@._\-]","", value)
        
        elif column_type == "url":
            cleaned= re.sub(r"[^a-zA-Z0-9:/._\-?=&]", "", value)
        
        elif column_type == "text":
            cleaned= re.sub(r"[^a-zA-Z0-9\s\-'.&]", "", value)

        elif column_type == "date":
            return value
        
        else:
            #fallback safe
            cleaned= re.sub(r"[^a-zA-Z0-9\s]", "", value)
        
        if cleaned == "":
            return None
        
        return cleaned
    
    df[column] = df[column].apply(clean_value)

    return df, []


def parse_currency_to_numeric(val):
    """Parses standard currency and shorthand values into pure float.
    Returns float or None if unparseable."""
    if pd.isna(val):
        return None
    s = str(val).strip()
    if not s:
        return None

    # Prefix patterns to strip: ₹, $, €, £, ¥, Rs. USD, EUR, etc.
    PREFIX = r"^[₹$€£¥\s]*(?:Rs\.?|USD|EUR|GBP|INR|AUD|CAD)?\s*"
    NUMBER = r"([\d,]+\.?\d*)"

    units = [
        (r"(?:Lakhs?|Lacs?|L)\b", 100_000),
        (r"(?:Crores?|Cr|C)\b", 10_000_000),
        (r"(?:Billions?|B|bn)\b", 1_000_000_000),
        (r"(?:Millions?|M|mn)\b", 1_000_000),
        (r"(?:Thousands?|K)\b", 1_000),
    ]

    for unit_pattern, multiplier in units:
        pattern = re.compile(PREFIX + NUMBER + r"\s*" + unit_pattern + r"\s*$", re.IGNORECASE)
        m = pattern.match(s)
        if m:
            try:
                return float(m.group(1).replace(",", "")) * multiplier
            except ValueError:
                pass

    # plain number case — strip prefix and commas
    plain = re.sub(r"^[₹$€£¥\s]*(?:Rs\.?|USD|EUR|GBP|INR|AUD|CAD)?\s*", "", s)
    plain = plain.replace(",", "")
    try:
        return float(plain)
    except ValueError:
        return None


def normalize_currency(df, column, column_type=None):
    """Normalises currency/number shorthand to plain floats.
    Values that don't match any pattern are left unchanged so validators can flag them."""
    df = df.copy()

    def convert(value):
        parsed = parse_currency_to_numeric(value)
        return parsed if parsed is not None else value

    df[column] = df[column].apply(convert)
    return df, []


def handle_missing(df, column, column_type=None, strategy="flag"):
    df = df.copy()
    errors = []

    null_mask = df[column].isna() | (df[column].astype(str).str.strip() == "")

    if not null_mask.any():
        return df, errors

    if strategy == "flag":
        # Moves row to invalid_df with a clear reason
        for idx in df[null_mask].index:
            errors.append({
                "rule": "handle_missing",
                "column": column,
                "row_index": idx,
                "message": f"Invalid: missing value in '{column}'",
                "outcome": "invalid"
            })

    elif strategy == "drop":
        # Moves row to removed_df (duplicate-style removal)
        for idx in df[null_mask].index:
            errors.append({
                "rule": "handle_missing",
                "column": column,
                "row_index": idx,
                "message": f"Dropped: missing value in '{column}'",
                "outcome": "removed"
            })

    elif strategy in ("median", "mean") and column_type == "numeric":
        parsed = df[column].apply(parse_currency_to_numeric)
        agg_val = parsed.median() if strategy == "median" else parsed.mean()

        if pd.notna(agg_val):
            # Fill only the null cells — leave non-null values untouched
            fill_mask = df[column].isna() | (df[column].astype(str).str.strip() == "")
            df.loc[fill_mask, column] = round(agg_val, 2)

    elif strategy == "placeholder":
        safe_types = ["text", "url"]
        fill_value = "Unknown" if column_type in safe_types else None
        if fill_value:
            df[column] = df[column].fillna(fill_value)
            df[column] = df[column].apply(
                lambda v: fill_value if str(v).strip() == "" else v
            )

    return df, errors

