import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.visited = set()
        self.attack_surface = []
        self.client = httpx.Client(follow_redirects=True)

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target).netloc

    def setup_dvwa(self):
        try:
            r = self.client.get(self.target + "/setup.php")
            soup = BeautifulSoup(r.text, "html.parser")
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input.get("value") if token_input else ""
            
            data = {"create_db": "Create / Reset Database"}
            if token:
                data["user_token"] = token
                
            resp = self.client.post(self.target + "/setup.php", data=data)
        except Exception as e:
            print(f"[!] Setup failed: {e}")
            pass

    def login_dvwa(self):
        try:
            login_url = urljoin(self.target, "/login.php")
            response = self.client.get(login_url)
            soup = BeautifulSoup(response.text, "html.parser")

            token_input = soup.find("input", {"name": "user_token"})
            token = token_input.get("value") if token_input else ""

            data = {
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token
            }

            self.client.post(login_url, data=data)
            # Force security low with correct scope
            self.client.cookies.set("security", "low", path="/")

        except Exception as e:
            print(f"[!] Login failed: {e}")
            pass

    def crawl(self, url):
        if url in self.visited:
            return
        
        if "logout" in url.lower():
            return

        self.visited.add(url)

        try:
            r = self.client.get(url, timeout=10)
        except Exception as e:
            print(f"[!] Warning: Failed to crawl {url}: {e}")
            return

        soup = BeautifulSoup(r.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").upper()

            if not action or action in ["#", "."]:
                full_url = url
            else:
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

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full = urljoin(url, href)
                if self.is_same_domain(full):
                    self.crawl(full)

    def run_generic(self):
        self.crawl(self.target)
        return self.attack_surface

    def run_dvwa(self):
        self.setup_dvwa()
        self.login_dvwa()

        self.crawl(self.target)

        dvwa_paths = [
            "/vulnerabilities/brute/",
            "/vulnerabilities/sqli/",
            "/vulnerabilities/sqli_blind/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
        ]

        for path in dvwa_paths:
            self.crawl(urljoin(self.target, path + "/"))

        return self.attack_surface

