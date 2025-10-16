################################################################################
# Netskope Client Log Summarizer
# Version: 1.0.0
#
# A Python script that parses Netskope Client debug logs (nsdebuglog*.log) to
# extract processes and their outbound destination hosts, and optionally
# performs URL category lookups using the Netskope URL Lookup API.
#
# It’s designed to help identify and understand the processes and destinations
# of traffic originating from endpoints protected by the Netskope Secure Web
# Gateway product, where custom traffic steering, SSL decryption, or
# Certificate Pinned App configurations might be relevant.
#
# Features:
#   - Parses multiple nsdebuglog*.log files
#   - Extracts process names and destination hosts, including ports
#   - Excludes traffic from Netskope Client processes
#   - Can perform URL category lookups using the Netskope URL Lookup API
#       Optionally filters out browser traffic, particularly valuable if limits
#       for the above API may be exceeded
#   - Outputs a detailed summary of each process and their respective traffic
#     destinations
#
# Requirements:
#   - Python 3.8 or higher
#   - Netskope API token with URL Lookup endpoint permissions
#
# Usage:
#   python3 netskope_log_summarizer.py
#
# Author: Peter Hayes
# License: MIT
#
# Disclaimer:
#   This project is not affiliated with or supported by Netskope.
#   It may be incomplete, outdated, or inaccurate.
#   Use at your own risk.
################################################################################

import json
import requests
import glob
import sys
from collections import defaultdict
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)


################################################################################
# CONFIGURATION - Edit these values to reflect your Netskope tenant details
################################################################################

@dataclass
class Config:
    """Edit the tenant_name and API token if using the URL (category) Lookup capability."""
    tenant_name: str = "example.goskope.com"
    api_token: str = "abc123"
    log_pattern: str = "nsdebuglog*.log"
    output_file: str = "processed_log_output.log"
    batch_size: int = 100
    daily_limit: int = 1000

    @property
    def api_url(self) -> str:
        return f"https://{self.tenant_name}/api/v2/nsiq/urllookup"

    ignored_processes: Set[str] = field(default_factory=lambda: {
        "netskope endpoint dlp",
        "netskope client",
        "netskopeclientgetwebcategoryappproxy",
        "epdlp.exe",
        "stagentui.exe",
        "stagentsvc.exe",
    })
    browser_processes: Set[str] = field(default_factory=lambda: {
        "firefox",
        "chrome",
        "opera",
        "edge",
        "chromium",
        "safari",
        "brave",
        "vivaldi",
        "arc",
        "comet",
        "iexplore"
    })


cfg = Config()


################################################################################
# HTTP SESSION SETUP WITH RETRY HANDLING
################################################################################

session = requests.Session()
retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retry))


################################################################################
# HELPER FUNCTIONS
################################################################################

def extract_destination(line: str) -> Tuple[str, str]:
    """
    Extract destination and preserve port if present.
    """
    try:
        process_part = line.split('process: ')[1]
        process = process_part.split(' to host: ')[0].strip().lower()

        host_part = process_part.split(' to host: ')[1]
        host = host_part.split(', addr: ')[0].strip()
        addr = host_part.split(', addr: ')[1].split(' to ')[0].strip()

        addr_host, _, addr_port = addr.partition(":")

        if host:
            destination = f"{host}:{addr_port}" if addr_port else host
        else:
            destination = addr

        return process, destination
    except (IndexError, ValueError):
        return "", ""


def parse_log_files() -> Dict[str, Set[str]]:
    """
    Parse all matching log files and extract processes with their destinations.
    """
    process_dest_map = defaultdict(set)
    log_files = glob.glob(cfg.log_pattern)

    if not log_files:
        print(f"No log files matching pattern '{cfg.log_pattern}' found.")
        sys.exit(1)

    for log_file in log_files:
        print(f"Processing log file: {log_file}")
        try:
            with open(log_file, 'r') as file:
                for line in file:
                    if 'process:' in line and 'to host:' in line:
                        process, destination = extract_destination(line)
                        if not process or not destination:
                            continue
                        if process in cfg.ignored_processes:
                            continue
                        process_dest_map[process].add(destination)
        except FileNotFoundError:
            print(f"Error: '{log_file}' not found. Skipping.")
        except Exception as e:
            print(f"Error while reading '{log_file}': {e}")

    return process_dest_map


def generate_output(process_dest_map: Dict[str, Set[str]], url_categories: Optional[Dict[str, str]]) -> None:
    """Generate the output file with processes and destinations."""
    try:
        with open(cfg.output_file, 'w') as file:
            for process, destinations in process_dest_map.items():
                file.write(f"Process: {process}\n")
                file.write(f"Destinations: {', '.join(destinations)}\n")

                if url_categories is not None:
                    for dest in destinations:
                        category = url_categories.get(dest.split(":")[0], "Unknown")
                        file.write(f"  - {dest}: {category}\n")

                file.write("\n")

        print(f"Processing completed. Check '{cfg.output_file}' for the results.")
    except OSError as e:
        print(f"Error writing output file '{cfg.output_file}': {e}")


def confirm_action(prompt: str) -> bool:
    """Prompt the user for a y/n response."""
    while True:
        response = input(prompt + " (y/n): ").strip().lower()
        if response in {"y", "n"}:
            return response == "y"
        print("Please enter 'y' or 'n'.")


def filter_browser_traffic(process_dest_map: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Filter out browser traffic if the user opts to exclude it."""
    return {
        process: destinations
        for process, destinations in process_dest_map.items()
        if not any(browser in process.lower() for browser in cfg.browser_processes)
    }


def log_api_error(e: Exception, response: Optional[requests.Response], payload: dict) -> None:
    """Log detailed API error response information."""
    print("Error during API call!")
    print("----------------------------------------------------------------------------------")
    print("| API Error Request Details")
    print("----------------------------------------------------------------------------------")
    print(f"API URL: {cfg.api_url}")
    print("Payload:")
    print(json.dumps(payload, indent=2))

    if response is not None:
        print("----------------------------------------------------------------------------------")
        print("| API Error Response Details")
        print("----------------------------------------------------------------------------------")
        print(f"Status Code: {response.status_code}")
        print("Headers:")
        print(response.headers)
        try:
            print("API Response:")
            print(response.content.decode('utf-8', errors='ignore'))
        except Exception as decode_error:
            print(f"Unable to decode response: {decode_error}")
    else:
        print("No response received from Netskope API endpoint.")

    print(f"Exception Details: {str(e)}")
    print("----------------------------------------------------------------------------------")


################################################################################
# URL CATEGORY LOOKUP (NETSKOPE API)
################################################################################

def fetch_categories(destinations: Set[str]) -> Optional[Dict[str, str]]:
    """Fetch categories for unique destination hosts via the API in batches."""
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Netskope-Api-Token': cfg.api_token
    }

    url_categories = {}
    destination_list = list(destinations)

    for i in range(0, len(destination_list), cfg.batch_size):
        batch = destination_list[i:i + cfg.batch_size]
        # Remove ports and ensure uniqueness within each batch
        unique_urls = list({dest.split(":")[0] for dest in batch})

        payload = {
            "query": {
                "disable_dns_lookup": True,
                "urls": unique_urls
            }
        }

        try:
            response = session.post(cfg.api_url, headers=headers, json=payload, timeout=10, verify=False)
            response.raise_for_status()

            results = response.json().get("result", [])
            for entry in results:
                url = entry.get("url", "").replace("https://", "")
                categories = ", ".join(cat.get("name", "Unknown") for cat in entry.get("categories", []))
                if url:
                    url_categories[url] = categories

        except requests.HTTPError as e:
            if response.status_code == 400 and "urls must contain unique values" in response.text.lower():
                print(f"Warning: Duplicate URLs detected in a batch {i // cfg.batch_size + 1}, skipping.")
                continue
            log_api_error(e, response, payload)
            print("Warning: Unable to lookup destination categories. Skipping further lookups.")
            return None
        except Exception as e:
            log_api_error(e, None, payload)
            return None

        print(f"Batch {i // cfg.batch_size + 1} complete ({len(unique_urls)} URLs).")

    return url_categories


################################################################################
# MAIN EXECUTION
################################################################################

def main() -> None:
    print("Parsing log files...")
    process_dest_map = parse_log_files()

    all_destinations = set(dest for dests in process_dest_map.values() for dest in dests)
    print(f"Found {len(all_destinations)} unique destination hosts across all processes.")

    if not confirm_action("Perform Netskope URL category lookups for discovered destination hosts?"):
        print("Skipping URL category lookups. Generating output without categories.")
        generate_output(process_dest_map, None)
        sys.exit(0)

    # -------------------------------------------------------------------------
    # Skip URL lookup if default placeholder tenant or API token is detected
    # -------------------------------------------------------------------------
    if cfg.tenant_name == "example.goskope.com" or cfg.api_token == "abc123":
        print("----------------------------------------------------------------------------------")
        print("Skipping URL category lookups because the default tenant FQDN or API token is set.")
        print("Please update 'tenant_name' and 'api_token' in the configuration section.")
        print("----------------------------------------------------------------------------------")
        generate_output(process_dest_map, None)
        sys.exit(0)

    if confirm_action("Do you want to exclude browser traffic?"):
        process_dest_map = filter_browser_traffic(process_dest_map)
        all_destinations = set(dest for dests in process_dest_map.values() for dest in dests)
        print(f"After excluding browser traffic, {len(all_destinations)} destination hosts remain.")

    if len(all_destinations) > 50:
        print(f"Warning: You're about to look up the URL category for {len(all_destinations)} destination hosts.")
        print(f"The URL category lookup API has a *daily* limit of {cfg.daily_limit}.")
        if not confirm_action("Do you want to continue?"):
            print("Exiting without performing any URL category lookups.")
            sys.exit(0)

    print(f"Performing URL category lookups for {len(all_destinations)} unique destination hosts...")
    url_categories = fetch_categories(all_destinations)

    print("Generating the output file...")
    generate_output(process_dest_map, url_categories)


if __name__ == "__main__":
    main()