import os
import tempfile
import pandas as pd
from app import process_cleaning_task, app, predict_rules_for_column

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
        {'first_name': 'Alice', 'last_name': 'A', 'email': 'alice@example.com', 'phone': '+12025550143', 'company': 'X'},
        {'first_name': 'Bob', 'last_name': 'B', 'email': 'invalid-email', 'phone': '202 555 0144', 'company': 'Y'},
        {'first_name': 'Charlie', 'last_name': 'C', 'email': 'charlie@example.com', 'phone': 'invalidphone', 'company': 'Z'},
    ])

    tmp = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
    tmp.close()
    df.to_excel(tmp.name, index=False)

    dummy = Dummy()
    result = process_cleaning_task.run.__func__(
        dummy, 
        tmp.name, 
        {'email': ['validate_email'], 'phone': ['validate_phone']}, 
        [], 
        'uploaded.xlsx', 
        1
    )

    assert isinstance(result, dict)
    # Charlie has an invalid phone number, Bob has an invalid email.
    # Alice should be the only fully valid one!
    # So valid: 1, invalid: 2
    assert result.get('total') == 3
    assert result.get('invalid') == 2
    assert result.get('valid') == 1
    assert 'file' in result

    # Read back the saved output file to verify inline standardization
    output_path = os.path.join("uploads", result['file'])
    df_cleaned = pd.read_excel(output_path, dtype=str)
    # Alice's phone +12025550143 was valid, and should remain +12025550143.
    # Let's verify Alice's phone number:
    assert df_cleaned.iloc[0]['phone'] == '+12025550143'

    # cleanup
    os.remove(tmp.name)
    if os.path.exists(output_path):
        os.remove(output_path)
    if result.get('invalid_file'):
        invalid_path = os.path.join("uploads", result['invalid_file'])
        if os.path.exists(invalid_path):
            os.remove(invalid_path)


def test_process_cleaning_task_duplicates():
    os.environ['SKIP_DB_INIT'] = '1'

    # Dataset designed to test duplicate checks:
    # 1. John Smith (Google)
    # 2. John Doe (Google) -> Same first name, different last name (should NOT trigger false duplicate drop)
    # 3. Alice Smith (Apple) -> Same last name, different first name (should NOT trigger false duplicate drop)
    # 4. John Smith (Google) -> Combined duplicate of row 1 (should be dropped)
    # 5. Empty names (should NOT be marked as duplicates of each other)
    # 6. Duplicate emails (should be evaluated individually and dropped)
    df = pd.DataFrame([
        {'first_name': 'John', 'last_name': 'Smith', 'email': 'john.smith@gmail.com', 'company': 'Google'},
        {'first_name': 'John', 'last_name': 'Doe', 'email': 'john.doe@gmail.com', 'company': 'Google'},
        {'first_name': 'Alice', 'last_name': 'Smith', 'email': 'alice.smith@gmail.com', 'company': 'Apple'},
        {'first_name': 'John', 'last_name': 'Smith', 'email': 'john.smith.copy@gmail.com', 'company': 'Google'},
        {'first_name': '', 'last_name': '', 'email': 'empty.name1@gmail.com', 'company': 'Google'},
        {'first_name': '', 'last_name': '', 'email': 'empty.name2@gmail.com', 'company': 'Google'},
        {'first_name': 'Bob', 'last_name': 'Baker', 'email': 'bob@gmail.com', 'company': 'Google'},
        {'first_name': 'Bob', 'last_name': 'Baker', 'email': 'bob@gmail.com', 'company': 'Google'}, # Duplicate email
    ])

    tmp = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
    tmp.close()
    df.to_excel(tmp.name, index=False)

    dummy = Dummy()
    # Apply drop_duplicates rules
    result = process_cleaning_task.run.__func__(
        dummy,
        tmp.name,
        {
            'first_name': ['drop_duplicates'],
            'last_name': ['drop_duplicates'],
            'email': ['drop_duplicates']
        },
        [],
        'uploaded_dup.xlsx',
        1
    )

    # Let's count how many are valid vs invalid.
    # Total rows = 8
    # - Row 1: John Smith (kept)
    # - Row 2: John Doe (kept, names joined, not duplicate of John Smith)
    # - Row 3: Alice Smith (kept, names joined, not duplicate of John Smith or John Doe)
    # - Row 4: John Smith (duplicate of Row 1, dropped)
    # - Row 5 & 6: empty names (kept, empty names are not duplicates)
    # - Row 7: Bob Baker (kept)
    # - Row 8: Bob Baker duplicate email (dropped due to individual email duplicate check)
    # So valid: 6, invalid: 2
    assert result.get('total') == 8
    assert result.get('valid') == 6
    assert result.get('invalid') == 2

    output_path = os.path.join("uploads", result['file'])
    df_cleaned = pd.read_excel(output_path, dtype=str)
    
    # Verify the remaining valid rows:
    first_names = df_cleaned['first_name'].fillna('').tolist()
    # Check that Row 4 John Smith was dropped, but Row 2 John and Row 3 Alice are kept:
    assert 'John' in first_names
    assert 'Alice' in first_names
    # We expect 2 rows with first name 'John' (John Smith and John Doe)
    assert len(df_cleaned[df_cleaned['first_name'] == 'John']) == 2
    # And only 1 row for John Smith specifically:
    assert len(df_cleaned[(df_cleaned['first_name'] == 'John') & (df_cleaned['last_name'] == 'Smith')]) == 1

    os.remove(tmp.name)
    if os.path.exists(output_path):
        os.remove(output_path)
    if result.get('invalid_file'):
        invalid_path = os.path.join("uploads", result['invalid_file'])
        if os.path.exists(invalid_path):
            os.remove(invalid_path)


def test_predict_rules_for_column():
    assert 'validate_email' in predict_rules_for_column('email_address')
    assert 'validate_phone' in predict_rules_for_column('Mobile Number')
    assert 'remove_specials' in predict_rules_for_column('first_name')
    assert 'drop_duplicates' in predict_rules_for_column('user_id')
    assert 'remove_specials' in predict_rules_for_column('company')


def test_fetch_columns_endpoint():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    os.makedirs('uploads', exist_ok=True)
    test_df = pd.DataFrame([
        {'first_name': 'Alice', 'last_name': 'Smith', 'age': '30'},
        {'first_name': 'Bob', 'last_name': 'Jones', 'age': '25'}
    ])
    test_filename = 'cleaned_test_fetch.xlsx'
    test_filepath = os.path.join('uploads', test_filename)
    test_df.to_excel(test_filepath, index=False)
    
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user_id'] = 1
            
        # 1. Fetch single column via GET
        resp = client.get(f'/fetch_columns?file={test_filename}&columns=first_name')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['file'] == test_filename
        assert data['fetched_columns'] == ['first_name']
        assert len(data['data']) == 2
        assert data['data'][0]['first_name'] == 'Alice'
        
        # 2. Fetch multiple columns via POST (JSON body)
        resp = client.post('/fetch_columns', json={
            'file': test_filename,
            'columns': ['first_name', 'last_name', 'missing_col']
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['fetched_columns'] == ['first_name', 'last_name']
        assert data['missing_columns'] == ['missing_col']
        assert data['data'][0]['first_name'] == 'Alice'
        assert data['data'][0]['last_name'] == 'Smith'
        
        # 3. Unauthenticated request
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get(f'/fetch_columns?file={test_filename}&columns=first_name')
        assert resp.status_code == 401

    # Cleanup
    if os.path.exists(test_filepath):
        os.remove(test_filepath)
