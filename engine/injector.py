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

            # Baseline request
            baseline_data = {p: "test" for p in target["params"]}
            baseline_resp = self.send(target["url"], target["method"], baseline_data)
            baseline_len = len(baseline_resp.text) if baseline_resp else 0

            for payload in payloads:
                data = {p: payload for p in target["params"]}
                response = self.send(target["url"], target["method"], data)

                if response:
                    self.results.append({
                        "url": target["url"],
                        "method": target["method"],
                        "payload": payload,
                        "status": response.status_code,
                        "length": len(response.text),
                        "baseline_length": baseline_len,
                        "snippet": response.text[:200]
                    })

        with open("evidence/responses.json", "w") as f:
            json.dump(self.results, f, indent=2)

        return self.results

