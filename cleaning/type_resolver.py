from cleaning.column_metadata import COLUMN_METADATA
from cleaning.schema_mapper import map_column_to_type
from cleaning.column_types import infer_column_type

def resolve_column_type(df, column_name):

    column_lower = column_name.lower()

    identifier_keywords = [
        "id","user_id","userid","record_id","transaction_id","serial","sno","rownum","row_number","index","serial no.", "sno.","s no.","sn","s.no","serial number"
    ]

    if any(keyword in column_lower for keyword in identifier_keywords):
        return "identifier"
    """
    Single source of tructh for column type resolution.
    Alias mapping first, fallbak to inference"""

    mapped_type = map_column_to_type(column_name, COLUMN_METADATA)
    if mapped_type:
        return mapped_type
    return infer_column_type(df[column_name])