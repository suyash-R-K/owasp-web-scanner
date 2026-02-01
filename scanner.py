from engine.crawler import Crawler
from engine.injector import Injector
from engine.analyzer import Analyzer

target = input("Enter target URL : ").strip()

crawler = Crawler(target)
surface = crawler.run()

print("[+] Attack surface size:", len(surface))

injector = Injector(surface, crawler.client)

# Run SQLi
injector.run("payloads/sqli.yaml")

# Run XSS
injector.run("payloads/xss.yaml")

analyzer = Analyzer(injector.results)
findings = analyzer.analyze()

print("\n[+] Vulnerabilities Found:")
if not findings:
    print("0 issues detected")
else:
    for f in findings:
        print(f"[{f.get('severity', 'UNK')}] {f['type']} ({f.get('confidence', 'UNK')})")
        print(f"  URL: {f['url']}")
        print(f"  Example Payload: {f['example_payload']}")
        print(f"  Detection Engines: {', '.join(f['engines'])}\n")


