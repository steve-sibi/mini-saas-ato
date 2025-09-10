import requests
APP = "https://YOURAPP.herokuapp.com"
users = [f"user{i}@example.com" for i in range(30)]
for u in users:
    requests.post(f"{APP}/login", data={"email":u, "password":"wrong"})
print("done")
