import pandas as pd
from cleaning.normalization import normalize_series

def calculate_completeness_score(row):
    """
    Score record completeness.
    More non-empty fields = higher score.
    Used for identity-priority retention."""
    return row.notna().sum()

def drop_duplicates(df, columns, column_type_map, mode="composite"):
    """
    -Support composite keys
    -Normalizes comparison values
    -Keeps most complete record"""

    if not columns:
        return df, pd.DataFrame()
    
    working_df = df.copy()

    #1.i) Normalize comparison columns
    normalized_df = working_df.copy()

    #ii) Normalize selected columns type-aware

    for col in columns:
        col_type = column_type_map.get(col, "text")

        normalized_df[col] = normalize_series(
            normalized_df[col],
            col_type=col_type
        )

    #2. Create composite key
    if mode == "composite":
        normalized_df["_dedupe_key"] = normalized_df[columns].astype(str).agg("|".join, axis=1)
    else:
        #treat each col independently
        normalized_df["_dedupe_key"] = normalized_df[columns[0]]
    
    
    #3. Attach key + completeness score
    working_df["_dedupe_key"] = normalized_df["_dedupe_key"]
    working_df["_completeness"] = working_df.notna().sum(axis=1)

    #4. Sort by key + completeness
    working_df = working_df.sort_values(
        by=["_dedupe_key", "_completeness"],
        ascending=[True, False]
    )

    #5. Drop duplicates correctly
    deduped_df = working_df.drop_duplicates(
        subset= "_dedupe_key",
        keep="first"
    )

    #Identify removed rows
    removed_rows = working_df.loc[~working_df.index.isin(deduped_df.index)].copy()

    #Improve tracebility
    master_lookup = working_df.groupby("_dedupe_key").head(1)
    master_map = master_lookup.set_index("_dedupe_key").index

    for idx in removed_rows.index:
        key = working_df.loc[idx,"_dedupe_key"]
        master_idx = working_df[working_df["_dedupe_key"] == key].index[0]

        removed_rows.loc[idx, "Removal Reason"] = (
            f"Duplicate of row {master_idx + 2} (based on {', '.join(columns)})"
        )

    #Cleanup helper cols
    deduped_df = deduped_df.drop(columns=["_dedupe_key", "_completeness"], errors="ignore")

    removed_rows = removed_rows.drop(columns=["_completeness"], errors="ignore")

    return deduped_df, removed_rows