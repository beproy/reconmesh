import httpx, re

ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
client = httpx.Client(timeout=30, headers={"User-Agent": ua}, follow_redirects=True)

r1 = client.get("https://ahmia.fi/search/")
print("homepage status:", r1.status_code)
print("homepage length:", len(r1.text))

pattern = r'<input type="hidden" name="([^"]+)" value="([^"]+)"'
m = re.search(pattern, r1.text)
print("token field:", m.group(1) if m else "NONE")
print("token value:", m.group(2) if m else "NONE")

params = {"q": "paypal"}
if m:
    params[m.group(1)] = m.group(2)

r2 = client.get("https://ahmia.fi/search/", params=params)
print("search status:", r2.status_code)
print("search length:", len(r2.text))
print("contains .onion:", ".onion" in r2.text)

idx = r2.text.find(".onion")
print("---context around first .onion---")
if idx > 0:
    print(r2.text[max(0, idx-300):idx+300])
else:
    print("no .onion in response")
