import yaml
import json
from bs4 import BeautifulSoup

class Injector:
    def __init__(self, attack_surface, client):
        self.attack_surface = attack_surface
        self.client = client   # shared authenticated httpx.Client
        self.results = []

    def load_payloads(self, path):
        with open(path) as f:
            return yaml.safe_load(f)

    def send(self, url, method, data):
        try:
            if method == "GET":
                return self.client.get(url, params=data, timeout=10)
            else:
                return self.client.post(url, data=data, timeout=10)
        except:
            return None

    def run(self, payload_file):
        payloads = self.load_payloads(payload_file)

        for target in self.attack_surface:

            # Fetch page with authenticated session to extract CSRF tokens
            try:
                page = self.client.get(target["url"])
            except:
                continue

            soup = BeautifulSoup(page.text, "html.parser")

            hidden = {}
            for inp in soup.find_all("input"):
                if inp.get("type") == "hidden":
                    hidden[inp.get("name")] = inp.get("value", "")

            # Baseline request
            baseline_data = {p: "test" for p in target["params"]}
            baseline_data.update(hidden)
            baseline_resp = self.send(target["url"], target["method"], baseline_data)
            baseline_len = len(baseline_resp.text) if baseline_resp else 0

            # Inject payloads
            for payload in payloads:
                for param in target["params"]:
                    # Don't fuzz hidden fields (CSRF tokens)
                    if param in hidden:
                        continue

                    data = baseline_data.copy()
                    data[param] = payload

                    response = self.send(target["url"], target["method"], data)

                    if response:
                        self.results.append({
                            "url": target["url"],
                            "method": target["method"],
                            "payload": payload,
                            "status": response.status_code,
                            "length": len(response.text),
                            "baseline_length": baseline_len,
                            "snippet": response.text[:50000]
                        })

        with open("evidence/responses.json", "w") as f:
            json.dump(self.results, f, indent=2)

        return self.results

