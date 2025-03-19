import argparse
import requests
import json
import tldextract
import urllib.parse
import whois
import time
import concurrent.futures
from pyfiglet import Figlet

# Fancy title
f = Figlet(font='slant')
print(f.renderText("Takeover?"))

# Argument parser setup
parser = argparse.ArgumentParser(description="Extract apex domains from crt.sh and verify with WHOIS.")
parser.add_argument("organization", help="The organization name to query on crt.sh.")
args = parser.parse_args()

# Fetch JSON data from crt.sh
def fetch_domains(organization):
    encoded_org = urllib.parse.quote(organization)
    url = f"https://crt.sh/?o={encoded_org}&output=json"
    
    retries = 5
    current_retries = 0

    while current_retries < retries:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            current_retries += 1
            print(f"❌ Failed to fetch data. HTTP {response.status_code}. Retrying in 10 seconds.. ({current_retries}/{retries})")
            time.sleep(10)

    print(f"❌ Failed to fetch data after 5 retries.. HTTP {response.status_code}")
    return None

# Extract unique apex domains
def extract_apex_domains(data):
    return sorted({
        f"{extract.domain}.{extract.suffix}".lower()
        for item in data if 'common_name' in item
        if (extract := tldextract.extract(item['common_name'])).domain and extract.suffix
    })

# WHOIS lookup & verification
def whois_lookup(domain, org_name):
    try:
        info = whois.whois(domain)

# Extraction of org in WHOIS fields
        org = getattr(info, "org", "N/A") if info.org else "N/A"
        org = org.lower() if org != "N/A" else "N/A"

        # Extraction of name servers in WHOIS fields
        name_servers = getattr(info, "name_servers", [])
        # If name_servers is a list, join them into a string or keep empty if None
        name_servers = [ns.strip().lower() for ns in name_servers] if isinstance(name_servers, list) else []

        # Extraction of emails in WHOIS fields
        emails = getattr(info, "emails", [])
        # If emails is a list, join them into a string or keep empty if None
        emails = [email.strip().lower() for email in emails] if isinstance(emails, list) else []

        # Verification checks
        org_match = org_name.lower() in org if org != "N/A" else False
        ns_match = any(org_name.lower() in ns for ns in name_servers) if name_servers else False
        email_match = any(org_name.lower() in email for email in emails) if emails else False


        # If the organization name is found in the "org" field, consider the domain verified
        if org_match or email_match or ns_match:
            print(f"✅ {domain} -> Verified (Org: {org}, Emails: {emails} NS: {name_servers})")
            return domain  # Return only verified domains
        else:
            print(f"⚠️ {domain} -> WHOIS Org: {org} Emails: {emails} NS: {name_servers} (No match)")

    except Exception as e:
        print(f"❌ WHOIS lookup failed for {domain}: {e}")

    return None  # Return nothing if not verified

# Parallel WHOIS verification
def verify_domains_parallel(domains, org_name):
    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda domain: whois_lookup(domain, org_name), domains))

    return [domain for domain in results if domain]  # Remove None values

# Main execution
data = fetch_domains(args.organization)

if data:
    apex_domains = extract_apex_domains(data)
    print(f"\n🔹 Found {len(apex_domains)} unique apex domains.")
    
    print("\n🔍 Running WHOIS verification in parallel...\n")
    verified_domains = verify_domains_parallel(apex_domains, args.organization)
    
    print(f"\n✅ Verified {len(verified_domains)} domains belonging to '{args.organization}'.")
