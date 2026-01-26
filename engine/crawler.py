import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.visited = set()
        self.attack_surface = []
        self.client = httpx.Client(follow_redirects=True)

    # DVWA login
    def login_dvwa(self):
        try:
            login_url = urljoin(self.target, "/login.php")
            
            # Fetch login page to get CSRF token
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
            
            resp = self.client.post(login_url, data=data, follow_redirects=True)
            
            if "Logout" in resp.text or "Welcome" in resp.text:
                print("[+] Logged into DVWA")
            else:
                print("[!] DVWA login failed (incorrect credentials or token)")
                
        except Exception as e:
            print(f"[!] DVWA login failed: {e}")

    def is_same_domain(self, url):
        return urlparse(url).netloc == urlparse(self.target).netloc

    def crawl(self, url):
        # Normalize URL to avoid loops
        url = url.split("?")[0].rstrip("/")
        
        if url in self.visited:
            return

        # Avoid logging out or resetting the DB
        exclude = ["logout.php", "setup.php", "login.php", "security.php"]
        if any(x in url for x in exclude):
            return

        print(f"[*] Crawling: {url}")
        self.visited.add(url)

        try:
            r = self.client.get(url, timeout=10)
        except:
            return

        soup = BeautifulSoup(r.text, "html.parser")

        # Extract forms
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").upper()

            # Correct DVWA form handling
            if not action or action == "#" or action == ".":
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

        # Follow links
        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full = urljoin(url, href)
                if self.is_same_domain(full):
                    self.crawl(full)

    def setup_dvwa(self):
        try:
            print("[*] Attempting to setup/reset DVWA database...")
            setup_url = urljoin(self.target, "/setup.php")
            resp = self.client.get(setup_url)
            soup = BeautifulSoup(resp.text, "html.parser")
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input.get("value") if token_input else ""
            
            data = {
                "create_db": "Create / Reset Database",
                "user_token": token
            }
            self.client.post(setup_url, data=data)
            print("[+] DVWA Database setup/reset completed")
        except Exception as e:
            print(f"[!] DVWA setup failed: {e}")

    def run(self):
        self.setup_dvwa()
        self.login_dvwa()
        self.crawl(self.target)

        # DVWA vulnerable pages
        dvwa_paths = [
            "/vulnerabilities/sqli/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
        ]

        for path in dvwa_paths:
            self.crawl(urljoin(self.target, path))

        return self.attack_surface

