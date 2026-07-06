import os

import pytest
import requests


@pytest.mark.skipif(
    not os.environ.get("RUN_RATE_LIMIT_SMOKE"),
    reason="manual smoke test; set RUN_RATE_LIMIT_SMOKE=1 to run against a live server",
)
def test_api_clean_rate_limit_smoke():
    token = os.environ.get("API_RATE_LIMIT_TOKEN")
    if not token:
        pytest.skip("set API_RATE_LIMIT_TOKEN to run this manual smoke test")

    url = os.environ.get("API_RATE_LIMIT_URL", "http://127.0.0.1:5000/api/clean")

    for attempt in range(70):
        response = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"selected_rules": []},
            timeout=10,
        )
        print(f"Request {attempt + 1}: {response.status_code}")
        if response.status_code == 429:
            print("Rate limit hit at request", attempt + 1)
            break