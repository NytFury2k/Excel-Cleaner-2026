
from .deduplication import drop_duplicates
from .type_resolver import resolve_column_type
from .rules_registry import RULES_REGISTRY
import pandas as pd
import re
from difflib import SequenceMatcher
from .survivorship import merge_cluster
from flask import flash, redirect, url_for


def canonicalize_value(value, column_type):
    """
    Normalise a single value for duplicate-comparison purposes.
    Kept here (rather than delegating to normalization.py) because it contains
    Gmail-specific dot/alias logic that normalization.py does not have.
    """
    if pd.isna(value):
        return value
    value = str(value).strip()

    if column_type == "email":
        value = value.lower()
        if "@" in value:
            local, domain = value.split("@", 1)
            if domain in ["gmail.com", "googlemail.com", "yahoo.com", "hotmail.com"]:
                local = local.split("+")[0]   # remove + aliases
                local = local.replace(".", "")  # remove dots
            domain = domain.lower()
            value = f"{local}@{domain}"

    elif column_type == "phone":
        value = re.sub(r"[^\d]", "", value)
        if value.startswith("91") and len(value) > 10:
            value = value[2:]

    elif column_type in ["text", "url"]:
        value = value.lower()
        value = re.sub(r"\s+", " ", value)

    return value


def text_similarity(a, b):
    if pd.isna(a) or pd.isna(b):
        return 0
    return SequenceMatcher(None, str(a), str(b)).ratio()


def normalize_for_fuzzy(text):
    if pd.isna(text):
        return ""
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def attach_error_columns(df, errors):
    if df.empty:
        return df

    error_map = {}

    for err in errors:
        idx = err.get("row_index")
        if idx is None:
            continue
        if idx not in error_map:
            error_map[idx] = {"rules": [], "messages": []}
        error_map[idx]["rules"].append(err["rule"])
        error_map[idx]["messages"].append(err["message"])

    def build_rule(idx):
        rules = error_map.get(idx, {}).get("rules", [])
        seen=[]
        for r in rules:
            if r not in seen:
                seen.append(r)

        if "fuzzy_duplicate" in seen:
            return "Duplicate (Fuzzy Match)"
        if "duplicate_removal" in seen:
            return "Duplicate"
        if rules:
            return ", ".join(seen)
        return ""

    def build_message(idx):
        messages = error_map.get(idx, {}).get("messages", [])
        if not messages:
            return ""
        seen=[]
        for m in messages:
            if m not in seen:
                seen.append(m)
        return "; ".join(seen)
    

    df["Rule(s) Failed"] = df.index.map(build_rule)
    df["Failure Reason"] = df.index.map(build_message)

    df["Rule(s) Failed"] = df["Rule(s) Failed"].replace("", "Duplicate")
    df["Failure Reason"] = df["Failure Reason"].replace(
        "", "Removed during deterministic deduplication"
    )

    return df


def run_cleaning_pipeline(df, selected_rules, duplicate_columns=None, duplicate_mode="composite", type_overrides=None):
    # print("NEW PIPELINE CALL")                                            #debug statements
    # print("SELECTED RULES AT FUNCTION START:", selected_rules)
    # print("LENGTH: ", len(selected_rules))

    # Guards
    if df is None or df.empty:
        return (pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), [], [], {})
    # Allow running the pipeline when only deduplication columns are provided
    if not selected_rules and not duplicate_columns:
        return (pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), [], [], {})

    cleaned_df = df.copy()
    invalid_df = pd.DataFrame(columns=df.columns)
    detailed_errors = []
    removed_duplicates = pd.DataFrame()

    # Normalise all rules to 3-tuples: (rule_name, column, extras)
    # extras is a strategy string for handle_missing, or an empty dict for everything else.
    # This lets us pass per-rule parameters without changing every function signature.
    selected_rules = [
        (r[0], r[1], r[2] if len(r) > 2 else {})
        for r in selected_rules
    ]

    # 1. Infer column types
    def _build_column_type_map(df, overrides=None):
        result = {}
        for col in df.columns:
            if overrides and col in overrides:
                result[col] = overrides[col]
            else:
                result[col] = resolve_column_type(df, col)
        return result 
    
    column_type_map = _build_column_type_map(df, overrides=type_overrides)
    # print("COL TYPES MAP: ", column_type_map)   #debug statement

    invalid_indices = set()
    incompatibility_errors = []
    valid_selected_rules = []

    # 2. COMPATIBILITY CHECK — build valid_selected_rules
    for rule_name, column, extras in selected_rules:
        rule_meta = RULES_REGISTRY.get(rule_name)
        if not rule_meta:
            continue
        if column not in cleaned_df.columns:
            continue

        column_type = column_type_map.get(column)

        if column_type == "identifier":
            if rule_name != "duplicate_identifier":
                incompatibility_errors.append({
                    "rule": rule_name,
                    "column": column,
                    "row_index": None,
                    "message": "Identifier columns cannot have cleaning rules applied"
                })
                continue

        allowed_types = rule_meta.get("allowed_types", [])
        if column_type not in allowed_types:
            incompatibility_errors.append({
                "rule": rule_name,
                "column": column,
                "row_index": None,
                "message": f"Incompatible rule '{rule_name}' for column type '{column_type}'"
            })
            continue

        valid_selected_rules.append((rule_name, column, extras))

    if not valid_selected_rules and not duplicate_columns:
        return (
            pd.DataFrame(),
            pd.DataFrame(),
            pd.DataFrame(),
            [],
            incompatibility_errors,
            {}
        )

    # 3. CLEANING PASS — runs BEFORE validation so rules like normalize_currency
    #    and handle_missing transform/fill values before validators see them.
    for rule_name, column, extras in valid_selected_rules:
        rule_meta = RULES_REGISTRY.get(rule_name)
        if not rule_meta or rule_meta.get("type") != "cleaning":
            continue
        if column not in cleaned_df.columns:
            continue
        try:
            # print("RUNNING CLEANING: ", rule_name, "on", column)    #debug statement
            if rule_name == "handle_missing":
                # extras is either the strategy string directly, or a dict with a "strategy" key
                strategy = extras if isinstance(extras, str) else extras.get("strategy", "flag")
                cleaned_df, errors = rule_meta["function"](
                    cleaned_df, column, column_type_map.get(column), strategy=strategy
                )
            else:
                cleaned_df, errors = rule_meta["function"](
                    cleaned_df, column, column_type_map.get(column)
                )
            detailed_errors.extend(errors)
        except Exception as e:
            detailed_errors.append({
                "rule": rule_name,
                "column": column,
                "row_index": None,
                "message": str(e)
            })

    # Handle handle_missing outcomes — these come from the cleaning pass
    # but need to route rows to invalid_df or removed_duplicates directly,
    # bypassing the normal validation split.
    missing_invalid_indices = set()
    missing_removed_indices = set()

    for err in detailed_errors:
        if err.get("rule") == "handle_missing":
            outcome = err.get("outcome")
            idx = err.get("row_index")
            if idx is None:
                continue
            if outcome == "invalid":
                missing_invalid_indices.add(idx)
            elif outcome == "removed":
                missing_removed_indices.add(idx)

    if missing_invalid_indices:
        flagged_df = cleaned_df.loc[list(missing_invalid_indices)].copy()
        invalid_df = pd.concat([invalid_df, flagged_df], ignore_index=False)
        cleaned_df = cleaned_df.drop(index=list(missing_invalid_indices))

    if missing_removed_indices:
        dropped_df = cleaned_df.loc[list(missing_removed_indices)].copy()
        removed_duplicates = pd.concat([removed_duplicates, dropped_df], ignore_index=False)
        cleaned_df = cleaned_df.drop(index=list(missing_removed_indices))


    # 4. VALIDATION PASS — runs on already-cleaned/normalised data
    for rule_name, column, extras in valid_selected_rules:
        rule_meta = RULES_REGISTRY.get(rule_name)
        if rule_meta.get("type") != "validation":
            continue
        try:
            failed_df, errors = rule_meta["function"](cleaned_df, column)
            invalid_indices.update(failed_df.index)
            detailed_errors.extend(errors)
        except Exception as e:
            detailed_errors.append({
                "rule": rule_name,
                "column": column,
                "row_index": None,
                "message": str(e)
            })

    # 5. SPLIT ONCE — after both cleaning and validation are complete
    if invalid_indices:
        new_invalid= cleaned_df.loc[list(invalid_indices)].copy()
        invalid_df = pd.concat([invalid_df, new_invalid], ignore_index=False)
        cleaned_df = cleaned_df.drop(index=list(invalid_indices)).copy()

    # 6. DEDUPE PASS
    if duplicate_columns:
        try:
            canonical_columns = {}

            for column in duplicate_columns:
                if column_type_map.get(column) == "identifier":
                    continue

                col_type = column_type_map.get(column)
                # Sanitize column name to create a safe temporary column
                safe_name = re.sub(r"[^0-9A-Za-z_]", "_", column)
                base_canonical = f"__canonical_{safe_name}"
                canonical_col = base_canonical
                # Avoid collisions with existing columns
                i = 1
                while canonical_col in cleaned_df.columns:
                    canonical_col = f"{base_canonical}_{i}"
                    i += 1

                cleaned_df[canonical_col] = cleaned_df[column].apply(
                    lambda x: canonicalize_value(x, col_type)
                )
                canonical_columns[column] = canonical_col

            # Add completeness priority score
            cleaned_df["__completeness_score"] = cleaned_df.notna().sum(axis=1)

            # Sort so most complete records come first
            cleaned_df = cleaned_df.sort_values(
                by="__completeness_score",
                ascending=False
            )

            subset_cols = list(canonical_columns.values())
            before_df = cleaned_df.copy()

            # Deterministic dedup first
            deduped_df = cleaned_df.drop_duplicates(
                subset=subset_cols,
                keep="first"
            )

            # Controlled fuzzy name matching — only inside same email/phone cluster
            identity_cols = [
                canonical_columns[col]
                for col in duplicate_columns
                if col in canonical_columns and column_type_map.get(col) in ["email", "phone"]
            ]

            text_columns = [
                col for col in duplicate_columns
                if column_type_map.get(col) == "text"
            ]

            rows_to_drop = []

            if identity_cols and text_columns:
                MAX_FUZZY_GROUP_SIZE = 20
                grouped = deduped_df.groupby(identity_cols)

                for _, group in grouped:
                    if len(group) > MAX_FUZZY_GROUP_SIZE:
                        print("Skipping fuzzy dedupe for large group: ", len(group))
                        continue

                    if len(group) <= 1:
                        continue

                    group = group.sort_values(
                        by="__completeness_score",
                        ascending=False
                    )
                    base_row = group.iloc[0]

                    for text_col in text_columns:
                        base_value = base_row[text_col]

                        for idx, row in group.iloc[1:].iterrows():
                            sim = text_similarity(
                                normalize_for_fuzzy(base_value),
                                normalize_for_fuzzy(row[text_col])
                            )
                            if sim >= 0.92:
                                rows_to_drop.append(idx)
                                detailed_errors.append({
                                    "rule": "fuzzy_duplicate",
                                    "column": text_col,
                                    "row_index": idx,
                                    "message": f"{text_col} matched with similarity {round(sim, 3)}",
                                    "confidence_score": round(sim, 3)
                                })

            if rows_to_drop:
                deduped_df = deduped_df.drop(index=rows_to_drop)

            # Track removed rows
            removed_duplicates = before_df.loc[
                ~before_df.index.isin(deduped_df.index)
            ].copy()

            for idx in removed_duplicates.index:
                detailed_errors.append({
                    "rule": "duplicate_removal",
                    "column": duplicate_columns,
                    "row_index": idx,
                    "message": "Removed during deterministic deduplication"
                })

            cleaned_df = deduped_df.copy()

            # Remove ALL temporary columns from both dataframes
            temp_cols = subset_cols + ["__completeness_score"]
            cleaned_df.drop(
                columns=[c for c in temp_cols if c in cleaned_df.columns],
                inplace=True
            )
            if not removed_duplicates.empty:
                removed_duplicates.drop(
                    columns=[c for c in temp_cols if c in removed_duplicates.columns],
                    inplace=True
                )

        except Exception as e:
            detailed_errors.append({
                "rule": "duplicate_removal",
                "column": duplicate_columns,
                "row_index": None,
                "message": str(e)
            })

    # 7. Attach error columns to invalid and removed dataframes
    invalid_df = attach_error_columns(invalid_df, detailed_errors)
    if not removed_duplicates.empty:
        removed_duplicates = attach_error_columns(removed_duplicates, detailed_errors)

    cleaning_summary = {
        "total_rows": len(df),
        "clean_rows": len(cleaned_df),
        "invalid_rows": len(invalid_df),
        "duplicate_rows_removed": len(removed_duplicates)
    }

    rule_counts = {}
    for err in detailed_errors:
        rule = err.get("rule")
        if rule:
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

    cleaning_summary["rules_trigger_counts"] = rule_counts
    print("\nCLEANING SUMMARY:", cleaning_summary, "\n")

    return cleaned_df, invalid_df, removed_duplicates, detailed_errors, incompatibility_errors, cleaning_summary