import os
import re
import sys
import json
import time
import requests
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Setup api key + cache + rate limit

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

console = Console()

CACHE_FILE = Path("cache.json")
CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours

# Cache 

def load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict) -> None:
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def get_cached_result(ioc: str, cache: dict):
    entry = cache.get(ioc)
    if not entry:
        return None
    age = time.time() - entry["timestamp"]
    if age > CACHE_TTL_SECONDS:
        return None  # expired
    return entry["data"]


def store_result(ioc: str, cache: dict, data: dict) -> None:
    cache[ioc] = {"timestamp": time.time(), "data": data}
    save_cache(cache)


# Retry when dealing rate-limited requests (if return 429)

def request_with_retry(method, url, max_retries=3, backoff_seconds=15, **kwargs):
    for attempt in range(1, max_retries + 1):
        resp = method(url, **kwargs)

        if resp.status_code != 429:
            return resp

        if attempt == max_retries:
            return resp  # give up after 3 failed tries

        wait_time = backoff_seconds * attempt  # 15s, 30s, 45s...
        console.print(
            f"[yellow]Rate limited (429). Waiting {wait_time}s before retry "
            f"{attempt}/{max_retries - 1}...[/yellow]"
        )
        time.sleep(wait_time)

    return resp


# IOC types

def classify_ioc(value: str) -> str:
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha1_pattern = r"^[a-fA-F0-9]{40}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"
    domain_pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"

    if re.match(ipv4_pattern, value):
        return "ip"
    elif re.match(md5_pattern, value) or re.match(sha1_pattern, value) or re.match(sha256_pattern, value):
        return "hash"
    elif re.match(domain_pattern, value):
        return "domain"
    else:
        return "unknown"


# query

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    if not VT_API_KEY:
        return {"error": "No VirusTotal API key set"}

    headers = {"x-apikey": VT_API_KEY}

    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return {"error": "Unsupported IOC type for VirusTotal"}

    try:
        resp = request_with_retry(requests.get, url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"VirusTotal returned {resp.status_code}"}
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception as e:
        return {"error": str(e)}


def query_abuseipdb(ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ip":
        return {"error": "AbuseIPDB only supports IPs"}
    if not ABUSEIPDB_API_KEY:
        return {"error": "No AbuseIPDB API key set"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}

    try:
        resp = request_with_retry(requests.get, url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return {"error": f"AbuseIPDB returned {resp.status_code}"}
        data = resp.json()["data"]
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "unknown"),
            "isp": data.get("isp", "unknown"),
        }
    except Exception as e:
        return {"error": str(e)}


def query_otx(ioc: str, ioc_type: str) -> dict:
    if not OTX_API_KEY:
        return {"error": "No OTX API key set"}

    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    if ioc_type == "ip":
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ioc}/general"
    elif ioc_type == "domain":
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general"
    elif ioc_type == "hash":
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{ioc}/general"
    else:
        return {"error": "Unsupported IOC type for OTX"}

    try:
        resp = request_with_retry(requests.get, url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"OTX returned {resp.status_code}"}
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {"pulse_count": pulse_count}
    except Exception as e:
        return {"error": str(e)}


# scoring 

def calculate_risk_score(vt: dict, abuse: dict, otx: dict) -> int:
    score = 0
    score += vt.get("malicious", 0) * 10
    score += vt.get("suspicious", 0) * 5
    score += abuse.get("abuse_confidence_score", 0)

   
    pulse_contribution = min(otx.get("pulse_count", 0), 5) * 2  # capped at 10 points max
    # OTX pulse_count is just "how many threat reports mention this IOC" 

    score += pulse_contribution
    return min(score, 100)  # max 100


# report cmd output

def print_report(ioc: str, ioc_type: str, vt: dict, abuse: dict, otx: dict, risk_score: int, from_cache: bool):
    cache_note = " [dim](from cache)[/dim]" if from_cache else ""
    console.print(Panel.fit(f"[bold]IOC:[/bold] {ioc}\n[bold]Type:[/bold] {ioc_type}{cache_note}", title="Threat Intel Report"))

    table = Table(title="Enrichment Results")
    table.add_column("Source", style="cyan")
    table.add_column("Result")

    if "error" in vt:
        table.add_row("VirusTotal", f"[yellow]{vt['error']}[/yellow]")
    else:
        table.add_row(
            "VirusTotal",
            f"malicious={vt['malicious']} suspicious={vt['suspicious']} harmless={vt['harmless']}",
        )

    if "error" in abuse:
        table.add_row("AbuseIPDB", f"[yellow]{abuse['error']}[/yellow]")
    else:
        table.add_row(
            "AbuseIPDB",
            f"confidence={abuse['abuse_confidence_score']}% reports={abuse['total_reports']} "
            f"country={abuse['country']} isp={abuse['isp']}",
        )

    if "error" in otx:
        table.add_row("OTX", f"[yellow]{otx['error']}[/yellow]")
    else:
        table.add_row("OTX", f"pulse_count={otx['pulse_count']}")

    console.print(table)

    if risk_score >= 70:
        verdict = "[bold red]HIGH RISK[/bold red]"
    elif risk_score >= 30:
        verdict = "[bold yellow]MEDIUM RISK[/bold yellow]"
    else:
        verdict = "[bold green]LOW RISK[/bold green]"

    console.print(Panel.fit(f"Risk Score: {risk_score}/100\nVerdict: {verdict}", title="Summary"))


# single IOC search (batch single the same)

def process_ioc(ioc: str, cache: dict) -> dict:
    ioc_type = classify_ioc(ioc)

    if ioc_type == "unknown":
        return {"ioc": ioc, "ioc_type": "unknown", "error": "Could not classify as IP, domain, or hash"}

    cached = get_cached_result(ioc, cache)

    if cached:
        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "vt": cached["vt"],
            "abuse": cached["abuse"],
            "otx": cached["otx"],
            "risk_score": cached["risk_score"],
            "from_cache": True,
        }

    vt_result = query_virustotal(ioc, ioc_type)
    abuse_result = query_abuseipdb(ioc, ioc_type)
    otx_result = query_otx(ioc, ioc_type)
    risk_score = calculate_risk_score(vt_result, abuse_result, otx_result)

    store_result(ioc, cache, {
        "vt": vt_result,
        "abuse": abuse_result,
        "otx": otx_result,
        "risk_score": risk_score,
    })

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "vt": vt_result,
        "abuse": abuse_result,
        "otx": otx_result,
        "risk_score": risk_score,
        "from_cache": False,
    }


def print_batch_summary(results: list) -> None:
    table = Table(title="Batch Scan Summary")
    table.add_column("IOC", style="cyan")
    table.add_column("Type")
    table.add_column("Risk Score")
    table.add_column("Verdict")

    for r in results:
        if "error" in r:
            table.add_row(r["ioc"], "unknown", "-", f"[yellow]{r['error']}[/yellow]")
            continue

        score = r["risk_score"]
        if score >= 70:
            verdict = "[bold red]HIGH RISK[/bold red]"
        elif score >= 30:
            verdict = "[bold yellow]MEDIUM RISK[/bold yellow]"
        else:
            verdict = "[bold green]LOW RISK[/bold green]"

        cache_note = " (cached)" if r.get("from_cache") else ""
        table.add_row(r["ioc"] + cache_note, r["ioc_type"], f"{score}/100", verdict)

    console.print(table)




# Main

def main():
    if len(sys.argv) != 3 and len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python threat-intel-tool.py <ip|domain|hash>")
        console.print("       python threat-intel-tool.py --file iocs.txt")
        sys.exit(1)

    cache = load_cache()

    # Batch mode
    if sys.argv[1] == "--file":
        if len(sys.argv) != 3:
            console.print("[red]Usage:[/red] python threat-intel-tool.py --file iocs.txt")
            sys.exit(1)

        file_path = Path(sys.argv[2])
        if not file_path.exists():
            console.print(f"[red]File not found:[/red] {file_path}")
            sys.exit(1)

        lines = [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines()]
        iocs = [line for line in lines if line and not line.startswith("#")]

        if not iocs:
            console.print("[yellow]No IOCs found in file.[/yellow]")
            sys.exit(0)

        console.print(f"[cyan]Loaded {len(iocs)} IOC(s) from {file_path}[/cyan]\n")

        results = []
        for i, ioc in enumerate(iocs, start=1):
            console.print(f"[cyan]({i}/{len(iocs)}) Checking {ioc}...[/cyan]")
            result = process_ioc(ioc, cache)
            results.append(result)
            if i < len(iocs) and not result.get("from_cache"):
                time.sleep(15)  #  VirusTotal free-tier limit is 4 requests/min

        console.print()
        print_batch_summary(results)
        return

    # Single IOC mode
    ioc = sys.argv[1].strip()
    result = process_ioc(ioc, cache)

    if "error" in result:
        console.print(f"[red]{result['error']}: '{ioc}'[/red]")
        sys.exit(1)

    console.print(f"[cyan]Classified as:[/cyan] {result['ioc_type']}")
    if result["from_cache"]:
        console.print("[cyan]Found recent cached result — skipping API calls.[/cyan]")
    else:
        console.print("[cyan]Querying sources...[/cyan]")

    print_report(
        result["ioc"], result["ioc_type"], result["vt"], result["abuse"],
        result["otx"], result["risk_score"], result["from_cache"],
    )


if __name__ == "__main__":
    main()