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
print("total length:", len(html))

# Find where the result list begins. Try common patterns.
for marker in ["<li class=\"result\"", "<ol id=\"ahmiaResultsList\"", "id=\"ahmiaResultsPage\"", "class=\"result\"", "<ol", "results found", "No results"]:
    idx = html.find(marker)
    print(f"  marker {marker!r}: index={idx}")

# Find the first .onion mention that is NOT the ahmia.fi about-page link.
# ahmia's own onion is juhanurmihxlp77...4csyd.onion — skip past it.
ahmia_own = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
search_from = 0
for _ in range(20):
    idx = html.find(".onion", search_from)
    if idx == -1:
        break
    start = max(0, idx - 80)
    end = min(len(html), idx + 80)
    context = html[start:end]
    if ahmia_own not in context:
        # Found a non-ahmia-own onion mention — likely a real result
        print(f"\n--- first real-looking .onion at index {idx} ---")
        big_start = max(0, idx - 1500)
        big_end = min(len(html), idx + 1500)
        print(html[big_start:big_end])
        break
    search_from = idx + 1
else:
    print("no non-ahmia .onion found in first 20 hits")
