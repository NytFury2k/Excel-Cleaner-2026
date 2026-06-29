from collections import Counter

def generate_summary(total_before, valid_after, error_messages):
    invalid_count = total_before - valid_after

    rule_counter = Counter(error_messages)

    summary = {
        "total_rows": total_before,
        "valid_rows": valid_after,
        "invalid_rows": invalid_count,
        "error_breakdown": dict(rule_counter)
    }

    return summary