import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

visited = set()

def crawl(url, max_links=10):

    urls_to_scan = []
    domain = urlparse(url).netloc

    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):

            href = link.get("href")
            full_url = urljoin(url, href)

            parsed = urlparse(full_url)

            # Stay in same domain
            if parsed.netloc != domain:
                continue

            # Avoid duplicates
            if full_url in visited:
                continue

            visited.add(full_url)
            urls_to_scan.append(full_url)

            if len(urls_to_scan) >= max_links:
                break

    except:
        pass

    return urls_to_scan
