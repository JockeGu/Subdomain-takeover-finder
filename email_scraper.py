"""
This script scrapes a website and outputs all found email addresses.
"""
import urllib.parse
import re
from collections import deque
import requests.exceptions
from bs4 import BeautifulSoup

INPUT_URL = str(input("Please enter target URL: "))
urls = deque([INPUT_URL])

scraped_urls = set()
emails = set()

COUNT = 0
try:
    while len(urls):
        COUNT += 1
        if COUNT == 20:
            break
        url = urls.popleft()
        scraped_urls.add(url)

        parts = urllib.parse.urlsplit(url)
        base_url = f"{parts.scheme}://{parts.netloc}"

        path = url[:url.rfind('/')+1] if '/' in parts.path else url

        print(f"[{COUNT}] Processing {url}")

        try:
            response = requests.get(url, timeout=5)
        except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
            continue

        new_email = set(re.findall(r'[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+', response.text, re.I))
        emails.update(new_email)

        soup = BeautifulSoup(response.text, features="lxml")

        for anchor in soup.find_all("a"):
            link = anchor.attrs['href'] if 'href' in anchor.attrs else ''
            if link.startswith('/'):
                link = base_url + link
            elif not link.startswith('http'):
                link = path + link
            if link not in urls and link not in scraped_urls:
                urls.append(link)

except KeyboardInterrupt:
    print("Closing..")

for mail in emails:
    print(mail)
