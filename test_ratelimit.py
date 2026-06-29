import requests

TOKEN="df8eb2e8b8d1c9af5cbc96aab10a37f34a6105426d84b7b4421c2d5104bbd21a"
URL="http://127.0.0.1:5000/api/clean"

for i in range(70):
    r = requests.post(URL, headers={"Authorization":f"Bearer {TOKEN}"},
                      json={"selected_rules":[]})
    print(f"Request {i+1}: {r.status_code}")
    if r.status_code == 429:
        print("Rate limit hit at request", i+1)
        break