```
pip install requests
```
#### Full run (org + domain)
```
python3 recon_suite.py -o "Apple Inc" -d apple.com
```

#### With API keys for deeper coverage
```
python3 recon_suite.py -o "Target Corp" -d target.com \
    --whoisxml-key YOUR_KEY \
    --github-token ghp_xxxx \
    --threads 20 --timeout 6
```

#### Domain-only, skip ASN phase
```
python3 recon_suite.py -d invest.miit.uz --skip-asn
```

#### Skip install if tools already present
```
python3 recon_suite.py -d target.com --no-install
```

#### Auto-installed tools
On first run it installs via apt + go install: amass, subfinder, dnsx, httpx, mapcidr, massdns, github-subdomains, jq, curl — no manual setup needed on Kali/Debian.

