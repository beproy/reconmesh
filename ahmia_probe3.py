import httpx, re

ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
client = httpx.Client(timeout=30, headers={"User-Agent": ua}, follow_redirects=True)

r1 = client.get("https://ahmia.fi/search/")
m = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', r1.text)
params = {"q": "paypal"}
if m:
    params[m.group(1)] = m.group(2)

r2 = client.get("https://ahmia.fi/search/", params=params)
html = r2.text

# Pull out the first 3 result blocks so we see real structure
pattern = re.compile(r'<li[^>]*class="result"[^>]*>(.*?)</li>', re.DOTALL | re.IGNORECASE)
matches = pattern.findall(html)
print(f"total result-block matches: {len(matches)}")
print()
for i, block in enumerate(matches[:3]):
    print(f"=== RESULT BLOCK #{i+1} ({len(block)} chars) ===")
    print(block[:2000])
    print()
