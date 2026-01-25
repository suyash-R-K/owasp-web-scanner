import httpx
import yaml
import json

class Injector:
    def __init__(self, attack_surface):
        self.attack_surface = attack_surface
        self.results = []

    def load_payloads(self, path):
        with open(path) as f:
            return yaml.safe_load(f)

    def send(self, url, method, data):
        try:
            if method == "GET":
                return httpx.get(url, params=data, timeout=10)
            else:
                return httpx.post(url, data=data, timeout=10)
        except:
            return None

    def run(self, payload_file):
        payloads = self.load_payloads(payload_file)

        for target in self.attack_surface:
            for payload in payloads:
                data = {}
                for p in target["params"]:
                    data[p] = payload

                response = self.send(target["url"], target["method"], data)

                if response:
                    self.results.append({
                        "url": target["url"],
                        "method": target["method"],
                        "payload": payload,
                        "status": response.status_code,
                        "length": len(response.text),
                        "snippet": response.text[:200]
                    })

        with open("evidence/responses.json", "w") as f:
            json.dump(self.results, f, indent=2)

        return self.results

