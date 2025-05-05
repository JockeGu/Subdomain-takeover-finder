import argparse
import requests
import tldextract
import urllib.parse
import whois
import time
import json
import csv
import concurrent.futures
import subprocess
import sys
import dns.resolver
from pyfiglet import Figlet

# Fancy title
f = Figlet(font='slant')
print(f.renderText("Takeover?"))

# Argument parser setup
parser = argparse.ArgumentParser(description="Extract apex domains from crt.sh or use a custom scope file.")
parser.add_argument("-o", "--organization", help="The organization name to query on crt.sh. (Required unless using -s/--scope-file)", required=False)
parser.add_argument("-s", "--scope-file", help="Path to a file containing pre-verified domains (one per line).", required=False)
parser.add_argument("-v", "--verbose", help="Enable detailed WHOIS output.", action="store_true")
parser.add_argument("-S", "--sublister", help="Enable subdomain search with Sublist3r", action="store_true")
parser.add_argument("-j", "--json-output", help="Enable output saved to json file (-j/--json-output 'FILENAME')", required=False, metavar="FILENAME", type=str)
parser.add_argument("-c", "--csv-output", help="Enable output saved to csv file (-c/--csv-output 'FILENAME')", required=False, metavar="FILENAME", type=str)
args = parser.parse_args()

# Ensure at least one method is provided
if not args.organization and not args.scope_file:
    parser.error("You must provide either -o/--organization or -s/--scope-file.")
# Only allow Sublist3r to run when using a scope file
if args.sublister and not args.scope_file:
    parser.error("Subdomain search is only available when providing a scope file with -s/--scope_file")
# Add extensions to filenames if not specified
if args.json_output and not args.json_output.endswith(".json"):
    args.json_output += ".json"
if args.csv_output and not args.csv_output.endswith(".csv"):
    args.csv_output += ".csv"

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

    print(f"❌💀 Failed to fetch data after {retries} retries.. HTTP {response.status_code}")
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

    return None  # Don't return if not verified

# Parallel WHOIS verification
def verify_domains_parallel(domains, org_name, verbose=False):
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda domain: whois_lookup(domain, org_name, verbose), domains))

    return [domain for domain in results if domain]  # Remove None values

# Read from scope file if one is provided
def read_scope_file(scope_file):
    try:
        with open(scope_file, "r") as file:
            return {line.strip().lower() for line in file if line.strip()}
    except Exception as e:
        print(f"❌💀 Failed to read scope file: {e}")
        return set()

def run_sublister(verified_domains):
    all_subdomains = []

    print("\n🔍 Running Sublist3r on provided domains...")

    for domain in verified_domains:
        print(f"🔹 Searching subdomains for: {domain}")

        try:
            # Run Sublist3r, (Change path if needed)
            result = subprocess.run(
                [sys.executable, "Sublist3r\sublist3r.py", "-d", domain],
                capture_output=True,
                text=True
            )
            # Extract subdomains from the output
            output = result.stdout.strip().split("\n")
            subdomains = [line for line in output if "." in line and " " not in line and not line.startswith("[!]")]

            all_subdomains.extend(subdomains)

            if args.verbose:
                print(f"🔹 Subdomains for {domain}:")
                for subdomain in subdomains:
                    print(f"- {subdomain}")

        except Exception as e:
            print(f"❌💀 Error running Sublist3r for {domain}: {e}")

    print(f"\n✅ Found a total of {len(all_subdomains)} subdomains.")
    return all_subdomains


# Patterns for potentially vulnerable cnames
VULN_CNAME_PATTERNS = [
    "s3.amazonaws.com",
    "s3-website-us-east-1.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "cloudfront.net",
    "herokudns.com",
    "herokussl.com",
    "ghs.googlehosted.com",
    "github.io",
    "pages.github.com",
    "netlify.com",
    "netlify.app",
    "render.com",
    "surge.sh",
    "pantheonsite.io",
    "fastly.net",
    "cdn.shopify.com",
    "myshopify.com",
    "c.storage.googleapis.com",
    "bigcartel.com",
    "readme.io",
    "zendesk.com",
    "desk.com",
    "helpscoutdocs.com",
    "hubspot.net",
    "marketo.com",
    "unbouncepages.com",
    "square.site",
    "shopify.com",
    "bigcommerce.com",
    "wordpress.com",
    "wixdns.net",
    "weebly.com",
    "strikinglydns.com",
    "custom.bnc.lt",
    "cname.vercel-dns.com",
    "awsdns-xx.org",  # Some AWS-hosted resources left misconfigured
    "azurefd.net",  # Azure Front Door
    "trafficmanager.net",  # Azure Traffic Manager
    "amazonaws.com",  # Wildcard catch in case of typoed buckets
    "sites.shopify.com",
    "domains.tumblr.com",
    "proposify.com",
    "wishpond.com",
    "bitbucket.io",
    "launchrock.com",
    "instapage.com",
    "webflow.io",
    "ghost.io",
]
# Error signatures to check for in http responses
ERROR_SIGNATURES = [
    "no such app",  
    "the specified bucket does not exist",  
    "there isn't a github pages site here",  
    "404 not found",  
    "this site can’t be reached",  
    "there is no app configured at this hostname",  
    "please renew your subscription",  
    "project not found",  
    "repository not found",  
    "error 1001: dns resolution error",  
    "this page is reserved for future use",  
    "the site you are looking for could not be found",  
    "forbidden - bucket not found",  
    "the requested url was not found on this server",  
    "the page you are looking for doesn't exist",  
    "not found - error 404",  
    "error: the page you are looking for does not exist",  
    "sorry, we couldn't find that page",  
    "unrecognized domain",  
    "your connection is not private",  
    "this account has been suspended",  
    "the feed has not been found",  
    "oops! we couldn’t find your site",  
    "oops, something went wrong",  
    "unknown domain",  
    "no application was found for this domain",  
    "site not found",  
    "domain is not configured",  
    "this domain is not connected to a site",  
    "there isn't a web site configured at this address",
    "sorry, this shop is currently unavailable",
    "this site is no longer available",
    "no such bucket",
    "not configured for this domain",
    "your domain isn't pointing to a site",
    "app not found",
    "domain has not been added to this project",
    "this domain is not verified",
    "the thing you're looking for isn't here",
    "page not configured",
    "invalid host",
    "there is nothing here",
    "invalid request",
    "404 error",
    "no such site at",
]

def get_cname(subdomain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"] # Use Google's and Cloudflares's DNS

    try:
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip('.')
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        try:
            # Fallback to checking A records
            answers = resolver.resolve(subdomain, 'A')
            return "A_RECORD_FOUND"
        except:
            return None
    except dns.exception.Timeout:
        return None
    except dns.resolver.NoNameservers:
        print(f"\n❌ No nameservers could resolve {subdomain}. Skipping...")
        return None
    
def check_takeover_risk(subdomain, cname):
    if cname:
        for pattern in VULN_CNAME_PATTERNS:
            if pattern in cname:
                print(f"⚠️  Possible takeover risk: {subdomain} → {cname}")
                return True
    else:
        return False

def check_http_responses(subdomain):
    urls = [f"http://{subdomain}/", f"https://{subdomain}/"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code in [404, 403]:
                print(f"HTTP {response.status_code} detected on {url} - Possible Takeover.")
                return True
            for sign in ERROR_SIGNATURES:
                if sign in response.text.lower():
                    print(f"❗Possible takeover on: {url}, Signature: {sign}")
                    return True
        except requests.exceptions.RequestException:
            pass
    return False


# Main execution
if args.scope_file:
    scope_domains = read_scope_file(args.scope_file)

    # Run Sublist3r
    if args.sublister:
        print("\n📂 Using provided scope file and running Sublist3r to find subdomains.")
        discovered_subdomains = run_sublister(scope_domains)

        # Check for takeovers
        takeover_findings = []
        if discovered_subdomains:
            print("\nChecking subdomains for potential takeovers...\n")

            for subdomain in discovered_subdomains:
                cname = get_cname(subdomain)

                if cname == "NXDOMAIN":
                    print(f"⚠️  {subdomain} does not exist. (NXDOMAIN)")
                elif cname and check_takeover_risk(subdomain, cname):
                    print(f"🔍 Verifying takeover possibility for: {subdomain} → {cname}")

                    http_risk = check_http_responses(subdomain)
                    
                    # Add findings to a list if json or csv options are enabled
                    if args.json_output or args.csv_output:
                        if http_risk:
                            takeover_findings.append({
                                "subdomain": subdomain,
                                "cname": cname,
                                "source": "CNAME + HTTP Status",
                                "note": "Potential takeover detected"
                            })
                        else:
                            takeover_findings.append({
                                "subdomain": subdomain,
                                "cname": cname,
                                "source": "CNAME only",
                                "note": "CNAME pattern matchen a vulnerable service"
                            })

        # Save detections to a JSON file if the option is enabled
        if args.json_output:
            if takeover_findings:
                print(f"\n👀 Detected {len(takeover_findings)} potential takeovers, 💾 saved to {args.json_output}..")
                with open(args.json_output, 'w') as jsonfile:
                    json.dump(takeover_findings, jsonfile, indent=4)
            else:
                print(f"\n❌💀 Finding list is empty.")
        else:
            False

        # Save detections to a CSV file if the option is enabled
        if args.csv_output:
            if takeover_findings:
                print(f"\n👀 Detected {len(takeover_findings)} potential takeovers, 💾 saved to {args.csv_output}..")
                with open(args.csv_output, 'w', newline='') as csvfile:
                    fieldnames = ["subdomain", "cname", "source", "note"]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in takeover_findings:
                        writer.writerow(row)
            else:
                print(f"\n❌💀 Finding list is empty.")
        else:
            False

else:
    data = fetch_domains(args.organization)

    if data:
        apex_domains = extract_apex_domains(data)
        print(f"\n🔹 Found {len(apex_domains)} unique apex domains.")

        print("\n🔍 Running WHOIS verification in parallel...\n")
        verified_domains = verify_domains_parallel(apex_domains, args.organization, args.verbose)

        print(f"\n✅ Verified {len(verified_domains)}/{len(apex_domains)} domains belonging to '{args.organization}'.")

# Print final verified domains
if args.organization:
    print(f"\n✅ Final verified domains ({len(verified_domains)} total):")
    for domain in verified_domains:
        print(f"  - {domain}")
