import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

def extract_cve_id(text: str):
    match = CVE_PATTERN.search(text)
    return match.group(0).upper() if match else None