import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, target):
        self.target = target
        self.visited = set()
        self.attack_surface = []

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target).netloc

    def crawl(self, url):
        if url in self.visited:
            return

        self.visited.add(url)

        try:
            r = httpx.get(url, timeout=10)
        except:
            return

        soup = BeautifulSoup(r.text, "html.parser")

        # Find all forms
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").upper()

            if not action:
                continue

            full_url = urljoin(url, action)

            params = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    params.append(name)

            self.attack_surface.append({
                "url": full_url,
                "method": method,
                "params": params
            })

        # Find all links
        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full = urljoin(url, href)
                if self.is_same_domain(full):
                    self.crawl(full)

    def run(self):
        self.crawl(self.target)
        return self.attack_surface

