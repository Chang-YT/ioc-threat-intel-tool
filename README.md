IOC Threat Intelligence Tool

Python cmd tool with input of IP address, domain, or file hash getting check by 3 threat intelligence sources to generate a risk report

# features

1 regex detects whether input is an IPv4 address/domain name/file hash (MD5/SHA1/SHA256)
2 using 3 diff websites - |VirusTotal| |AbuseIPDB| |AlienVault OTX| 
3 opinion from all 3 website combine into one score 0-100 
VirusTotal and AbuseIPDB are trusted more because those are more reliable
OTX is trusted less because it might include innocent factors in an accident
4 caching results within 6 hour will be saved in file `cache.json` to avoid wasting API quota on deplicated lookups
5 batch lookup enable scanning a whole list of IOCs from a text file in one run
6 rate limit is used because of the free-tier API limits, system will automatically retries when encounter with HTTP 429 responses, and batch requests is paced between checks so it won't hit the limit.


# Requirements

- Python 3.10+
- Free API keys from:
  - [VirusTotal]
  - [AbuseIPDB]
  - [AlienVault OTX]
  

# batch lookup
for example

8.8.8.8
example.com
44d88612fea8a8f36de82e1278abb02f
----or----
python threat-intel-tool.py --file iocs.txt


# risk scoring

|               Signal               |         Weight        |
|  VirusTotal — malicious detections |      ×10 per vendor   |
| VirusTotal — suspicious detections |      ×5 per vendor    |
| AbuseIPDB — abuse confidence score |    ×1 (0–100 scale)   |
|      OTX — pulse (report) mentions |          ×2           |**capped at 5 pulses (10 pts max)

**OTX pulse?
it goes up whenever an IOC shows up in 'any' threat report!! also when Cloudflare IP mentioned in a report because attackers happened to route traffic through X_X

scoring board:
0-29 → LOW RISK
30-69 → MEDIUM RISK
70-100 → HIGH RISK

## current limitation
1 using free-tier API limits apply (VirusTotal: 4 req/min; AbuseIPDB: 1,000/day), so request much not reach these limits
2 this risk scoring is for only demonstration purposes, and is not under production level

# improvement

1 export results to HTML/PDF reports
2 add more sources? maybe---> Shodan, GreyNoise, URLhaus
3 use SQLite-backed cache instead of JSON for bigger datasets