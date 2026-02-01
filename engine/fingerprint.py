import httpx

class Fingerprinter:
    def __init__(self, target):
        self.target = target.rstrip("/")

    def detect(self):
        # DVWA fingerprint
        try:
            r = httpx.get(self.target + "/login.php", timeout=5)
            if "Damn Vulnerable Web Application" in r.text:
                return "dvwa"
        except:
            pass

        # Juice Shop fingerprint
        try:
            r = httpx.get(self.target + "/rest/user/login", timeout=5)
            if "juice" in r.text.lower():
                return "juice-shop"
        except:
            pass

        return "generic"

