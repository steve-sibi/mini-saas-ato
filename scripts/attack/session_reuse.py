import requests
APP = "https://YOURAPP.herokuapp.com"
s = requests.Session()
# Legit login to get a cookie
s.post(f"{APP}/register", data={"email":"alice@example.com","password":"P@ssw0rd!"})
s.post(f"{APP}/login", data={"email":"alice@example.com","password":"P@ssw0rd!"})
cookie = s.cookies.get_dict()

# Reuse the cookie in a second session (pretend different device)
s2 = requests.Session()
s2.cookies.update(cookie)
print(s2.get(f"{APP}/dashboard").status_code)
