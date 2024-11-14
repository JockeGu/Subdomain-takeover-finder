import argparse
import requests
import json
import tldextract
import urllib.parse
from pyfiglet import Figlet


f = Figlet(font='slant')
print(f.renderText("crt.sh Apex Download"))

# Set up argument parser
parser = argparse.ArgumentParser(description="Download a JSON file from crt.sh based on the organization name, extract apex domains, and save the results.")
parser.add_argument("organization", help="The organization name to query on crt.sh.")
parser.add_argument("-o", "--output", help="The output file name to save the extracted domains.", default="output_domains.txt")

# Parse the arguments
args = parser.parse_args()

# Function to download the JSON file
def download_file(organization, output_filename):
    # URL encode the organization name to handle spaces and special characters
    encoded_organization = urllib.parse.quote(organization)
    
    # Construct the exact URL
    url = f"https://crt.sh/?o={encoded_organization}&output=json"
    
    print(f"Downloading from: {url}")
    
    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Write the content of the response to a file
        with open(output_filename, 'wb') as file:
            file.write(response.content)
        print(f"File downloaded successfully and saved as '{output_filename}'.")
    else:
        print(f"Failed to download file. HTTP Status code: {response.status_code}")
        return None
    return output_filename

# Function to extract domains from a JSON file
def extract_domains_from_json(json_file):
    with open(json_file, 'r') as file:
        data = json.load(file)

    # Assuming the JSON contains an array of objects, each with a 'common_name' field
    domains = [item['common_name'] for item in data if 'common_name' in item]
    return domains

# Function to extract apex domains from a list of domains
def extract_apex_domains(domains):
    seen = set()
    apex_domains = [
        f"{extract.domain}.{extract.suffix}".lower()  # Concatenates domain and suffix to get the apex domain
        for domain in domains
        if (extract := tldextract.extract(domain)).domain and extract.suffix
        and not (f"{extract.domain}.{extract.suffix}".lower() in seen or seen.add(f"{extract.domain}.{extract.suffix}".lower()))
    ]
    return sorted(apex_domains)

# Main execution
downloaded_file = download_file(args.organization, "downloaded.json")

if downloaded_file:
    # Extract domains from the downloaded JSON file
    domains = extract_domains_from_json(downloaded_file)

    # Extract apex domains from the list of domains
    apex_domains = extract_apex_domains(domains)

    # Write the apex domains to the output file
    with open(args.output, 'w') as output_file:
        output_file.write("\n".join(apex_domains))
    print(f"Apex domains extracted and saved to '{args.output}'.")
