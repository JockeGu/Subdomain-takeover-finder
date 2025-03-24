import argparse
import requests
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
parser = argparse.ArgumentParser(description="Extract apex domains from crt.sh or use a custom scope file.")
parser.add_argument("-o", "--organization", help="The organization name to query on crt.sh. (Required unless using -s/--scope-file)", required=False)
parser.add_argument("-s", "--scope-file", help="Path to a file containing pre-verified domains (one per line).", required=False)
parser.add_argument("-v", "--verbose", help="Enable detailed WHOIS output.", action="store_true")
args = parser.parse_args()

# Ensure at least one method is provided
if not args.organization and not args.scope_file:
    parser.error("You must provide either -o/--organization or -s/--scope-file.")

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

    print(f"❌ Failed to fetch data after {retries} retries.. HTTP {response.status_code}")
    return None

# Extract unique apex domains
def extract_apex_domains(data):
    return sorted({
        f"{extract.domain}.{extract.suffix}".lower()
        for item in data if 'common_name' in item
        if (extract := tldextract.extract(item['common_name'])).domain and extract.suffix
    })

# WHOIS lookup & verification
def whois_lookup(domain, org_name, verbose=False):
    try:
        info = whois.whois(domain)

        # Extraction of org in WHOIS fields
        org = getattr(info, "org", "N/A") if info.org else "N/A"
        org = org.lower() if org != "N/A" else "N/A"

        # Extraction of name servers in WHOIS fields
        name_servers = getattr(info, "name_servers", [])
        name_servers = [ns.strip().lower() for ns in name_servers] if isinstance(name_servers, list) else []

        # Extraction of emails in WHOIS fields
        emails = getattr(info, "emails", [])
        emails = [email.strip().lower() for email in emails] if isinstance(emails, list) else []

        # Verification checks
        org_match = org_name.lower() in org if org != "N/A" else False
        ns_match = any(org_name.lower() in ns for ns in name_servers) if name_servers else False
        email_match = any(org_name.lower() in email for email in emails) if emails else False

        # If the organization name is found in the "org" field, consider the domain verified
        if org_match or email_match or ns_match:
            if verbose:
                print(f"✅ {domain} -> Verified (Org: {org}, Emails: {emails}, NS: {name_servers})")
            return domain  # Return only verified domains
        else:
            if verbose:
                print(f"⚠️ {domain} -> WHOIS Org: {org}, Emails: {emails}, NS: {name_servers} (No match)")

    except Exception as e:
        if verbose:
            print(f"❌ WHOIS lookup failed for {domain}: {e}")

    return None  # Return nothing if not verified

# Parallel WHOIS verification
def verify_domains_parallel(domains, org_name, verbose=False):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda domain: whois_lookup(domain, org_name, verbose), domains))

    return [domain for domain in results if domain]  # Remove None values

# Load scope file if provided
def load_scope_file(scope_file):
    try:
        with open(scope_file, "r") as file:
            return {line.strip().lower() for line in file if line.strip()}
    except Exception as e:
        print(f"❌ Failed to read scope file: {e}")
        return set()

# Main execution
if args.scope_file:
    print("\n📂 Using provided scope file.")
    verified_domains = load_scope_file(args.scope_file)
else:
    data = fetch_domains(args.organization)

    if data:
        apex_domains = extract_apex_domains(data)
        print(f"\n🔹 Found {len(apex_domains)} unique apex domains.")

        print("\n🔍 Running WHOIS verification in parallel...\n")
        verified_domains = verify_domains_parallel(apex_domains, args.organization, args.verbose)

        print(f"\n✅ Verified {len(verified_domains)}/{len(apex_domains)} domains belonging to '{args.organization}'.")

# Print final verified domains
print(f"\n✅ Final verified domains ({len(verified_domains)} total):")
for domain in verified_domains:
    print(f"  - {domain}")
