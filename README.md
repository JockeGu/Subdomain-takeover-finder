# 🔎 Subdomain Takeover Finder

This tool helps security testers and bug bounty hunters automate the process of identifying potentially vulnerable subdomains that may be susceptible to subdomain takeover attacks. It can be used in both internal testing scenarios and public bug bounty program assessments.

---

## ✨ Features

- **Discover domains** via [crt.sh](https://crt.sh) or by uploading your own scope file.
- **Verify domain ownership** using WHOIS data to filter out irrelevant or false positives.
- **Enumerate subdomains** using [Sublist3r](https://github.com/aboul3la/Sublist3r) *(only when using scope file)*.
- **Check CNAME records** for signs of external services that are known to be takeover-prone.
- **Analyze HTTP responses** for error messages that suggest an inactive service.
- **Export results** to `.json` or `.csv` for further analysis or reporting.

---

## ⚙️ Usage

```bash
# Fetch and verify domains from crt.sh
python sub_takeover.py -o "Organization Name"

# Use custom scope file and run Sublist3r
python sub_takeover.py -s scope.txt -S
```

## ⚙️ Command Line Options
| Argument               | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| `-o`, `--organization` | Query crt.sh for organization name                         |
| `-s`, `--scope-file`   | Use custom domain scope from a `.txt` file                 |
| `-S`, `--sublister`    | Run Sublist3r subdomain discovery *(only valid with `-s`)* |
| `-v`, `--verbose`      | Print verbose output (WHOIS info, subdomains, etc.)        |
| `-j`, `--json-output`  | Save results to JSON file (e.g. `results.json`)            |
| `-c`, `--csv-output`   | Save results to CSV file (e.g. `results.csv`)              |


## 🧪 Example
```bash
python sub_takeover.py -s scope.txt -S -v -j findings.json -c findings.csv
````

## 📦 Requirements
Python 3.x and the following libraries:

-requests

-tldextract

-whois

-dnspython

-pyfiglet

You can install them via:

````bash
pip install -r requirements.txt
````

⚠️ Note: Sublist3r must be cloned and available in the same directory or correctly referenced in the script.

##❓ What is a Subdomain Takeover?
A subdomain takeover occurs when a subdomain (like shop.example.com) points to a third-party service (e.g., GitHub Pages, AWS S3, Netlify) that is no longer in use. If the DNS record still exists but the service is unclaimed, an attacker may register it and hijack the subdomain.

This tool identifies such DNS misconfigurations and provides indicators of possible takeover risks.

## 📄 Output
Each detected risk is saved with the following structure:

-subdomain – the affected subdomain

-cname – the CNAME value or pointer

-source – method of detection (CNAME only, CNAME + HTTP Status, etc.)

-note – short description

## ✅ Example Output (JSON)
````json

[
  {
    "subdomain": "blog.example.com",
    "cname": "ghs.googlehosted.com",
    "source": "CNAME + HTTP Status",
    "note": "Potential takeover detected"
  }
]
````
## 📚 Disclaimer
This project is intended for educational and ethical testing purposes only. Use responsibly and within the scope of permission.

## 🙌 Contributions
Feel free to open issues or submit PRs if you find bugs or want to suggest improvements!

  
