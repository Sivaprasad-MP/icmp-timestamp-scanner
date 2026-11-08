# ICMP Timestamp Scanner

Python 3.10+ command-line scanner for IPv4 ICMP timestamp disclosure. Sends type 13 requests and reports validated type 14 responses. Exports an Excel workbook with per-IP results, VLAN summary, and interpretation notes. No Npcap or Scapy dependency.

## Windows CMD

Open Command Prompt **as Administrator**, then:

```cmd
cd C:\Users\Sivaprasad\icmp-timestamp-scanner
py -m pip install -r requirements.txt
py icmp_timestamp.py --ip 192.168.1.10 --output single_ip.xlsx
py icmp_timestamp.py --subnet 192.168.10.0/24 --vlan 10 --output vlan10.xlsx
copy vlans.example.csv vlans.csv
notepad vlans.csv
py icmp_timestamp.py --vlan-file vlans.csv --output all_vlans.xlsx
```

Edit the example addresses to match your network. Scan only networks you administer or have permission to test.

CSV format (multiple subnets may share the same VLAN label):

```csv
vlan,subnet
10,192.168.10.0/24
20,192.168.20.0/24
```

Preview scope without elevation or network traffic:

```cmd
py icmp_timestamp.py --vlan-file vlans.csv --dry-run
```

Optional settings: `--timeout 1 --attempts 2 --delay 0.05 --max-hosts 65536`.
Scanning is sequential; an unresponsive /24 takes about 9 minutes at defaults. Retries apply to hosts without a valid response. Ctrl+C saves completed hosts as a partial report. Close the output workbook before rerunning.

Linux: install requirements with `python3 -m pip install -r requirements.txt` in your preferred environment, then run the scanner with the necessary raw-socket privileges, e.g. `sudo /path/to/venv/bin/python icmp_timestamp.py --ip 192.168.1.10`.

## Results

- **EXPOSED**: matching type 14, code 0 reply with valid checksum, source, identifier, sequence and originate timestamp. Timestamp service is reachable from this scan location.
- **NO_REPLY**: inconclusive. Host may be offline, filtered, experiencing packet loss, or have timestamp replies disabled. This is not proof of remediation.
- **ERROR**: local socket/send/receive error; inspect Details and repeat the check.

Report includes VLAN label, subnet, IP, UTC check time, status, attempts, RTT, raw originate/receive/transmit fields, and details. Timestamp fields are milliseconds since UTC midnight in the standard format; a high bit can indicate nonstandard time. The tool reports exposure, not clock accuracy.

VLAN membership is supplied by your CSV. The tool follows operating-system routes; it does not discover VLANs, add 802.1Q tags, or select switch ports. Ensure your scan machine can reach each subnet. Overlapping address spaces on isolated VLANs require running from each appropriate network context.

The protocol format is defined by [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html). To address exposure, configure the relevant host/network firewall to filter timestamp requests and replies (ICMP types 13 and 14), then retest from the relevant network location.

Exit codes: 0 = scan finished (including exposed hosts), 2 = input/dependency/socket/report error or per-host errors, 130 = interrupted with partial report.

## Tests

```cmd
py -m unittest discover -s tests -v
```

Tests use synthetic replies and mocked sockets; they do not scan a network.
