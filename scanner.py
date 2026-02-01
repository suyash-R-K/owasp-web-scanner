from engine.fingerprint import Fingerprinter
from engine.crawler import Crawler
from engine.injector import Injector
from engine.analyzer import Analyzer
from engine.report import generate_report

target = input("Enter target URL : ").strip()

fingerprint = Fingerprinter(target).detect()
print(f"[+] Target profile: {fingerprint}")
print(f"[debug] using {'run_dvwa' if fingerprint == 'dvwa' else 'run_generic'}")


crawler = Crawler(target)

if fingerprint == "dvwa":
    surface = crawler.run_dvwa()
else:
    surface = crawler.run_generic()

print(f"[+] Attack surface size: {len(surface)}")

injector = Injector(surface, crawler.client)
injector.run("payloads/sqli.yaml")
injector.run("payloads/xss.yaml")

analyzer = Analyzer(injector.results)
findings = analyzer.analyze()

print("\n[+] Vulnerabilities Found:")
if not findings:
    print("0 issues detected")
else:
    for f in findings:
        print(f"[{f.get('severity','UNK')}] {f['type']} ({f.get('confidence','UNK')})")
        print(f"  URL: {f['url']}")
        print(f"  Example Payload: {f.get('example_payload','')}")
        print(f"  Detection Engines: {', '.join(f.get('engines',[]))}\n")

generate_report()

