import os
import tempfile
import pandas as pd
from app import process_cleaning_task

class Dummy:
    def __init__(self):
        self.states = []
    def update_state(self, state, meta=None):
        self.states.append((state, meta))


def test_process_cleaning_task_basic():
    # Ensure DB actions are skipped
    os.environ['SKIP_DB_INIT'] = '1'

    # Create a temporary Excel file
    df = pd.DataFrame([
        {'first_name': 'Alice', 'last_name': 'A', 'email': 'alice@example.com', 'phone': '+1234567890', 'company': 'X'},
        {'first_name': 'Bob', 'last_name': 'B', 'email': 'invalid-email', 'phone': '+1987654321', 'company': 'Y'},
        {'first_name': 'Charlie', 'last_name': 'C', 'email': 'charlie@example.com', 'phone': '+1098765432', 'company': 'Z'},
    ])

    tmp = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
    tmp.close()
    df.to_excel(tmp.name, index=False)

    dummy = Dummy()
    result = process_cleaning_task(dummy, tmp.name, {'email': ['validate_email']}, [], 'uploaded.xlsx', 1)

    assert isinstance(result, dict)
    assert result.get('total') == 3
    assert result.get('invalid') == 1
    assert result.get('valid') == 2
    assert 'file' in result

    # cleanup
    os.remove(tmp.name)
