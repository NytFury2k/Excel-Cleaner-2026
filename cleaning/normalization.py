import re
import pandas as pd
from urllib.parse import urlparse, urlunparse

def normalize_series(series, col_type="text"):
    """
    Normalize values for duplicate comparison.
    Lowercase, strip, collapse spaces. Canonicalizes, not validates """

    #preserve real nulls
    s = series.copy()

    #convert to string only where not null
    s = s.where(s.isna(), s.astype(str))

    #base strip
    s = s.str.strip()

    if col_type == "email":
        return _normalize_email(s)
    
    if col_type == "phone":
        return _normalize_phone(s)
    
    if col_type == "url":
        return _normalize_url(s)
    
    if col_type == "text":
        return _normalize_text(s)
    
    if col_type == "numeric":

        def clean_numeric(val):
            if pd.isna(val):
                return val
            
            val =  str(val).strip().lower()

            #Remove currency symbols and commas
            val = re.sub(r"[₹$,]", "", val)

            #Handle shorthand like 65k
            match_k = re.match(r"(\d+(\.\d+)?)k", val)
            if match_k:
                return float(match_k.group(1)) * 1000
            
            #Convert words to number (basic suport)
            word_map = {
                "thousand": 1000,
                "hundred" : 100,
                "million" : 1000000,
                "lakh" : 100000
            }

            for word, multiplier in word_map.items():
                if word in val:
                    digits = re.findall(r"\d+", val)
                    if digits:
                        return float(digits[0]) * multiplier
                    
            #Try direct converison
            try:
                return float(val)
            except:
                return val    #letting validation layer catch it
            
        return s.apply(clean_numeric)
    
    return s

def _normalize_email(series):
    series = series.str.lower()

    #Remove accidental spaces
    series = series.str.replace(r"\s+", "", regex=True)

    return series

def _normalize_phone(series):

    #Remove all non-digits
    series = series.str.replace(r"\D", "", regex=True)

    #Remove leading zeros if excessive
    series = series.str.lstrip("0")

    return series

def _normalize_url(series):

    def clean_url(url):
        if pd.isna(url):
            return url
        
        url = url.strip().lower()

        if not url.startswith(("http://","https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)

            #Remove trailing slash from path
            path = parsed.path.rstrip("/")

            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc,
                path,
                '',
                '',
                ''
            ))
            return normalized
        
        except:
            return url
    
    return series.apply(clean_url)

def _normalize_text(series):
    series = series.str.lower()
    series = series.str.replace(r"\s+", " ", regex=True)
    return series


def canonicalize_value(value, column_type):
    """
    Single-value wrapper around normalize_series for use in engine.py. Replaces the duplicate canonicalize_value defined in engine.py"""

    if pd.isna(value):
        return value
    
    s = pd.Series([value])
    result = normalize_series(s, col_type=column_type)
    return result.iloc[0]