import pytest
import pandas as pd
import numpy as np

# Import project modules
from cleaning.engine import canonicalize_value, run_cleaning_pipeline
from cleaning.rules_registry import RULES_REGISTRY
from cleaning.validations import validate_email, validate_phone
from cleaning.cleaning_rules import trim_whitespace, clean_special_chars, handle_missing, normalize_currency
from cleaning.deduplication import drop_duplicates
from rbac import has_permission, ROLE_PERMISSIONS
from helpers import validate_password
import app as app_module

# ── 1. CLEANING ENGINE & RULES TESTS ─────────────────────────────────────────

def test_canonicalize_value():
    """Test email, phone, and text canonicalization logic."""
    assert canonicalize_value("  John.Doe+test@gmail.com  ", "email") == "johndoe@gmail.com"
    assert canonicalize_value("+91 98765-43210", "phone") == "9876543210"
    assert canonicalize_value("  HELLO   WORLD  ", "text") == "hello world"

def test_trim_whitespace_rule():
    """Test whitespace trimming on dataframe column."""
    df = pd.DataFrame({"email": ["  john@example.com  ", "   test   "]})
    cleaned_df, errors = trim_whitespace(df, "email", "email")
    assert cleaned_df["email"][0] == "john@example.com"
    assert cleaned_df["email"][1] == "test"
    assert errors == []

def test_clean_special_chars_rule():
    """Test removing special characters from dataframe column."""
    df = pd.DataFrame({"text": ["hello@world!", "foo#bar$"]})
    cleaned_df, errors = clean_special_chars(df, "text", "text")
    assert cleaned_df["text"][0] == "helloworld"

def test_handle_missing_values():
    """Test missing value handler strategies."""
    df = pd.DataFrame({"text": ["A", None, "B"]})
    cleaned_df, errors = handle_missing(df, "text", "text", strategy="placeholder")
    assert cleaned_df["text"][1] == "Unknown"

def test_normalize_currency():
    """Test currency string normalization to clean numbers."""
    df = pd.DataFrame({"numeric": ["$1,250.50", "₹500"]})
    cleaned_df, errors = normalize_currency(df, "numeric", "numeric")
    assert float(cleaned_df["numeric"][0]) == 1250.50
    assert float(cleaned_df["numeric"][1]) == 500.0

def test_deduplication():
    """Test duplicate dropping rule."""
    df = pd.DataFrame({
        "email": ["test@example.com", "test@example.com", "other@example.com"],
        "name": ["Alice", "Alice", "Bob"]
    })
    deduped_df, removed_rows = drop_duplicates(df, columns=["email"], column_type_map={"email": "email"})
    assert len(deduped_df) == 2
    assert len(removed_rows) == 1

def test_rules_registry_coverage():
    """Verify that all rules in RULES_REGISTRY are correctly structured."""
    for rule_key, rule_meta in RULES_REGISTRY.items():
        assert "label" in rule_meta
        assert "function" in rule_meta
        assert callable(rule_meta["function"])
        assert "type" in rule_meta
        assert "allowed_types" in rule_meta

def test_run_cleaning_pipeline():
    """Run full cleaning pipeline on sample dataset."""
    df = pd.DataFrame({
        "email": ["  Alice@Example.com ", "invalid-email", "bob@example.com"],
        "phone": ["+91 9999988888", "12345", "9999988888"]
    })
    
    column_types = {"email": "email", "phone": "phone"}
    rules_json = {
        "email": ["trim_whitespace", "validate_email"],
        "phone": ["validate_phone"]
    }
    
    cleaned_df, invalid_df, removed_duplicates, detailed_errors, incompatibility_errors, cleaning_summary = run_cleaning_pipeline(
        df, column_types, rules_json
    )
    
    assert isinstance(cleaned_df, pd.DataFrame)
    assert isinstance(invalid_df, pd.DataFrame)
    assert isinstance(removed_duplicates, pd.DataFrame)
    assert "total_rows" in cleaning_summary

# ── 2. ROLE-BASED ACCESS CONTROL (RBAC) TESTS ─────────────────────────────

def test_rbac_permissions(client):
    """Test RBAC role permissions structure in Flask session context."""
    with app_module.app.test_request_context():
        from flask import session
        session["permissions"] = list(ROLE_PERMISSIONS["admin"])
        assert has_permission("create_user") == True

        session["permissions"] = list(ROLE_PERMISSIONS["user"])
        assert has_permission("create_user") == False

# ── 3. HELPER & VALIDATION TESTS ───────────────────────────────────────────

def test_password_validation():
    """Test secure password validation rules."""
    # Valid password
    errors = validate_password("StrongP@ss123")
    assert len(errors) == 0

    # Invalid password (no special char, no uppercase)
    invalid_errors = validate_password("weak1234")
    assert len(invalid_errors) > 0

# ── 4. FLASK ROUTE & INTEGRATION TESTS ────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    """Flask test client fixture with mocked database connection."""
    class FakeCursor:
        def execute(self, *args, **kwargs):
            return None
        def fetchall(self):
            return []
        def fetchone(self):
            return {"id": 1, "username": "admin", "role": "admin", "password": "hashed_password", "is_active": 1}
        def close(self):
            return None

    class FakeConnection:
        def cursor(self, dictionary=True, dict=False):
            return FakeCursor()
        def commit(self):
            pass
        def rollback(self):
            pass
        def close(self):
            pass

    monkeypatch.setattr(app_module, "get_db_connection", lambda: FakeConnection())
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client

def test_login_page_renders(client):
    """Test GET / or /login renders interface."""
    res = client.get("/", follow_redirects=True)
    assert res.status_code == 200

def test_unauthenticated_protected_route_redirects(client):
    """Test unauthenticated request to protected route redirects."""
    res = client.get("/admin/create-user", follow_redirects=False)
    assert res.status_code == 302
