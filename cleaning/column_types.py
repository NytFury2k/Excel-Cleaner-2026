import re
import pandas as pd

TYPE_PATTERNS = {
    "email" : r'^[\w\.-]+@[\w\.-]+\.\w+$',
    "phone" : r'^\+?\d{7,15}$',
    "url" : r'^(https?://)?(www\.)?[A-Za-z0-9-]+\.[A-Za-z]{2,}(\S*)?$'

}

def infer_column_type(series):
    """
    Infer col type using sample-based pattern detection.
    Designed to be replacable with DB-driven metadata later.
    If pandas already parsed the col as datetime when reading the Excel, trust that- no need to sample-check"""

    if pd.api.types.is_datetime64_any_dtype(series):
        return "date"
    
    sample = series.dropna().astype(str).str.strip().head(25)

    if sample.empty:
        return "text"
    
    for col_type, pattern in TYPE_PATTERNS.items():
        matches = sample.str.match(pattern).sum()
        if matches >= len(sample) * 0.6:
            return col_type
        
    #Strict numeric detection (80%)
    numeric_count = 0
    for value in sample:
        cleaned = re.sub(r"[^\d\.\-]","",str(value))
        try:
            float(cleaned)
            numeric_count += 1
        except:
            pass

    if numeric_count >= len(sample) * 0.6:
        return "numeric"

    
    #date detection(80%)
    date_converted = pd.to_datetime(sample, errors="coerce", dayfirst=True)
    if date_converted.notna().sum() >= len(sample) * 0.8:
        return "date"

    return "text"
   
