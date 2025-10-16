# netskope-client-log-summarizer
A Python script that parses Netskope Client debug logs (nsdebuglog*.log) to extract processes and their outbound destination hosts, and optionally performs URL category lookups using the Netskope URL Lookup API.

It’s designed to help identify and understand the processes and destinations of traffic originating from endpoints protected by the Netskope Secure Web Gateway product, where custom traffic steering, SSL decryption, or Certificate Pinned App configurations might be relevant.

## Features
- Parses multiple nsdebuglog*.log files
- Extracts process names and destination hosts, including ports
- Excludes traffic from Netskope Client processes
- Can perform URL category lookups using the Netskope URL Lookup API
  - Optionally filters out browser traffic, particularly valuable if limits for the above API may be exceeded
- Outputs a detailed summary of each process and their respective traffic destinations 

## Usage

## Notes
- Since the script summarizes traffic steered through Netskope, any observed traffic already configured as a steering bypass for the Netskope Client will be excluded from the output.
- The Netskope [URL Lookup API](https://docs.netskope.com/en/url-lookup), available to all Netskope Secure Web Gateway customers, supports up to 100 URLs per request and a total of 1,000 URLs per day. The script can process more than 100 lookups by batching requests, warns the user about the daily limit, and includes an option to filter out browser traffic that may not be relevant.
- The URL Lookup API may not be enabled for all Netskope tenants. If the API endpoint is unavailable when generating API credentials, contact your account representative or technical support team for assistance.

## License
Licensed under MIT — free to use, modify, and share, with no warranty.

## Disclaimer
This project is **not affiliated with or supported by Netskope**. It may be incomplete, outdated, or inaccurate. Use at your own risk.
