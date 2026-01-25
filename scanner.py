from engine.crawler import Crawler
from engine.injector import Injector

target = "http://127.0.0.1"

crawler = Crawler(target)
surface = crawler.run()

print("[+] Attack surface:")
print(surface)

injector = Injector(surface)
results = injector.run("payloads/sqli.yaml")

print("\n[+] Injection results:")
for r in results:
    print(r["url"], r["payload"], r["status"], r["length"])

