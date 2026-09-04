import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from app import database
from app.seed import seed

database.init_db()
seed()

from app.services.analyzer import UrlAnalyzer

analyzer = UrlAnalyzer(org_id=1)
tests = [
    "https://maybank2u.com/",
    "https://www.microsoft.com/",
    "https://www.google.com/",
    "https://examp1e.com/login",
    "https://example-secure.com",
    "https://example-login.com",
    "https://example.co",
    "https://example.com@malicious.com/steal",
    "https://xn--exmple-6pa.com/",
    "https://secure-information.malicious.ru",
    "https://randombrandxyz.com/",
    "https://c1tibank.com/secure/login",
    "https://paypa1-secure.com/",
    "https://пaypal.com/",
    "https://еxample.com/",
    "https://xn--xample-2of.com/",
]
for t in tests:
    r = analyzer.analyze(t, source="TEST").to_dict()
    first = r["reasons"][0][:66] if r["reasons"] else ""
    print(
        f"{r['risk_score']:3d} {r['classification']:11s} {t[:44]:46s} "
        f"m={str(r['matched_domain']):22s} | {first}"
    )