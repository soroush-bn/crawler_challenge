import os
import re

BASE_URL = os.environ["CRAWL_BASE_URL"]     
USERNAME = os.environ["CRAWL_USERNAME"]
PASSWORD = os.environ["CRAWL_PASSWORD"]
PAGE_LIMIT = 10

RESOURCE_DATA_FILENAME = "resource_data.json"
FINDINGS_FILENAME = "findings.json"
FLAG_PATTERN = re.compile(r"^VISUALPING\{[0-9a-fA-F]{16}\}$")
KNOWN_DECOY = "VISUALPING{0000deadbeef0000}"
