import pandas as pd

def choose_best_value(values):
    """
    Pick best value based on completeness and length
    
    Priority:
    1. Not-null values
    2. Longer values (more complete)
    3. Most frequent value
    """

    clean_values = [
        v for v in values if not v in [None,"", "nan"] and pd.notna(v)
    ]

    if not clean_values:
        return None
    
    #Frequency score
    value_counts = {}

    for v in clean_values:
        value_counts[v] = value_counts.get(v,0)+1

    #Sort by frequency then length
    best_value = sorted(
        clean_values,
        key=lambda x: (value_counts[x], len(str(x))),
        reverse= True
    )[0]

    return best_value


def merge_cluster(group):
    """
    Merge duplicate rows field-by-field using survivorship rules."""

    merged = {}

    for column in group.columns:
        merged[column] = choose_best_value(group[column].tolist())

    return merged