import requests

APP = "https://mini-ato-saas-3190e0d8aaa2.herokuapp.com"
users = [f"user{i}@example.com" for i in range(30)]
for u in users:
    requests.post(f"{APP}/login", data={"email": u, "password": "wrong"})
print("done")
