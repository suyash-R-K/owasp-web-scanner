from engine.crawler import Crawler
from engine.injector import Injector
from engine.analyzer import Analyzer

target = "http://127.0.0.1:3000"  # Juice Shop or DVWA

crawler = Crawler(target)
surface = crawler.run()

injector = Injector(surface)
responses = injector.run("payloads/sqli.yaml")

analyzer = Analyzer(responses)
findings = analyzer.analyze()


print("\n[+] Vulnerabilities Found:")

if not findings:
    print("0 issues detected")
else:
    for f in findings:
        print(f["type"], f["url"], f["payload"])

