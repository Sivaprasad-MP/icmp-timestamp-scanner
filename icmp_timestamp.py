#!/usr/bin/env python3
"""Check IPv4 ICMP timestamp exposure and export Excel reports."""
import argparse
import csv
import ipaddress
import math
from pathlib import Path
import secrets
import socket
import struct
import sys
import time
from collections import Counter
from datetime import datetime, timezone


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def request(identifier, sequence, originate):
    packet = struct.pack('!BBHHHIII', 13, 0, 0, identifier, sequence, originate, 0, 0)
    return packet[:2] + struct.pack('!H', checksum(packet)) + packet[4:]


def parse_reply(data, source, target, identifier, sequence, originate):
    """Validate IPv4 header and correlate a complete timestamp response."""
    if source != target or len(data) < 40 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 15) * 4
    length = struct.unpack('!H', data[2:4])[0]
    if ihl < 20 or length < ihl + 20 or len(data) < length or data[9] != 1:
        return None
    if socket.inet_ntoa(data[12:16]) != target:
        return None
    if struct.unpack('!H', data[6:8])[0] & 0x3fff:
        return None
    body = data[ihl:length]
    if checksum(body) != 0:
        return None
    kind, code, _, ident, seq, orig, received, transmitted = struct.unpack('!BBHHHIII', body[:20])
    if (kind, code, ident, seq, orig) != (14, 0, identifier, sequence, originate):
        return None
    return received, transmitted


def probe(sock, target, timeout, attempts):
    for attempt in range(1, attempts + 1):
        identifier, sequence = secrets.randbelow(65536), secrets.randbelow(65536)
        originate = int(time.time() * 1000) % 86400000
        started = time.monotonic()
        try:
            sock.sendto(request(identifier, sequence, originate), (target, 0))
            deadline = started + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    break
                reply = parse_reply(data, addr[0], target, identifier, sequence, originate)
                if reply is not None:
                    return ('EXPOSED', attempt, round((time.monotonic() - started) * 1000, 2),
                            originate, *reply, 'Matching ICMP type 14 reply received')
        except OSError as exc:
            return ('ERROR', attempt, None, None, None, None, str(exc))
    return ('NO_REPLY', attempts, None, None, None, None,
            'No matching reply; offline, filtered, packet loss, or timestamp disabled')


def targets(args):
    networks = []
    if args.ip:
        networks.append((args.vlan, ipaddress.IPv4Network(str(ipaddress.IPv4Address(args.ip)) + '/32')))
    elif args.subnet:
        networks.append((args.vlan, ipaddress.IPv4Network(args.subnet, strict=True)))
    else:
        with open(args.vlan_file, newline='', encoding='utf-8-sig') as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not {'vlan', 'subnet'}.issubset(reader.fieldnames):
                raise ValueError('VLAN CSV must contain vlan,subnet headers')
            for line, row in enumerate(reader, 2):
                if not row.get('vlan') or not row.get('subnet'):
                    raise ValueError(f'Missing VLAN or subnet on CSV line {line}')
                networks.append((row['vlan'].strip(), ipaddress.IPv4Network(row['subnet'].strip(), strict=True)))
    count = sum(n.num_addresses if n.prefixlen >= 31 else n.num_addresses - 2 for _, n in networks)
    if not count:
        raise ValueError('No targets supplied')
    if count > args.max_hosts:
        raise ValueError(f'{count} targets exceeds --max-hosts {args.max_hosts}')
    seen = set()
    for vlan, network in networks:
        for ip in network.hosts():
            key = (vlan, str(ip))
            if key not in seen:
                seen.add(key)
                yield vlan, str(network), str(ip)


HEADERS = ['VLAN', 'Subnet', 'IP', 'Checked UTC', 'Status', 'Attempts', 'RTT ms',
           'Originate ms', 'Receive ms', 'Transmit ms', 'Details']


def export(rows, output, interrupted=False):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    book = Workbook()
    details = book.active
    details.title = 'Results'
    details.append(HEADERS)
    for row in rows:
        details.append(row)
    summary = book.create_sheet('VLAN Summary')
    summary.append(['VLAN', 'Scanned', 'EXPOSED', 'NO_REPLY', 'ERROR'])
    counts = {}
    for row in rows:
        counts.setdefault(row[0], Counter())[row[4]] += 1
    for vlan, statuses in counts.items():
        summary.append([vlan, sum(statuses.values()), statuses['EXPOSED'], statuses['NO_REPLY'], statuses['ERROR']])
    notes = book.create_sheet('Scan Notes')
    notes.append(['Item', 'Value'])
    notes.append(['Scan state', 'Interrupted: partial results' if interrupted else 'Completed'])
    notes.append(['EXPOSED', 'Validated type 14 reply to a type 13 request'])
    notes.append(['NO_REPLY', 'Inconclusive: offline, filtering, packet loss, or timestamp disabled'])
    notes.append(['VLAN', 'User supplied label; scanning follows OS routes, without VLAN tagging'])
    notes.append(['Timestamps', 'Raw unsigned fields; high bit can indicate nonstandard time'])
    for sheet in book:
        sheet.freeze_panes = 'A2'
        sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]:
            cell.font = Font(bold=True, color='FFFFFF')
            cell.fill = PatternFill('solid', fgColor='234567')
        for column in sheet.columns:
            sheet.column_dimensions[column[0].column_letter].width = min(75, max(14, max(len(str(c.value or '')) for c in column) + 2))
        for cells in sheet.iter_rows(min_row=2):
            for cell in cells:
                # Store user-controlled strings as text, never as Excel formulas.
                if isinstance(cell.value, str):
                    cell.data_type = 's'
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    try:
        book.save(temporary)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', help='Single IPv4 address')
    group.add_argument('--subnet', help='IPv4 CIDR, e.g. 192.168.10.0/24')
    group.add_argument('--vlan-file', help='CSV with vlan,subnet columns')
    parser.add_argument('--vlan', default='Unassigned', help='Label for --ip or --subnet')
    parser.add_argument('--output', default='icmp_timestamp_results.xlsx')
    parser.add_argument('--timeout', type=float, default=1.0, help='Seconds per attempt (default 1)')
    parser.add_argument('--attempts', type=int, default=2)
    parser.add_argument('--delay', type=float, default=0.05, help='Seconds between hosts')
    parser.add_argument('--max-hosts', type=int, default=65536)
    parser.add_argument('--dry-run', action='store_true', help='List targets without packets or Excel output')
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not math.isfinite(args.delay) or args.delay < 0 or args.attempts < 1 or args.max_hosts < 1:
        parser.error('Timeout, attempts, max-hosts must be positive; delay must be nonnegative')
    if Path(args.output).suffix.lower() != '.xlsx':
        parser.error('--output must end in .xlsx')
    try:
        planned = list(targets(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.dry_run:
        for target in planned:
            print(','.join(target))
        print(f'{len(planned)} target(s); no packets sent')
        return 0
    try:
        import openpyxl  # Check dependency before starting any scan.
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except ImportError:
        print('Install dependency: py -m pip install -r requirements.txt', file=sys.stderr)
        return 2
    except OSError as exc:
        print(f'Cannot open ICMP socket: {exc}. Run CMD as Administrator (Linux: sudo).', file=sys.stderr)
        return 2
    rows, interrupted = [], False
    try:
        with sock:
            for index, (vlan, subnet, ip) in enumerate(planned, 1):
                result = probe(sock, ip, args.timeout, args.attempts)
                row = [vlan, subnet, ip, datetime.now(timezone.utc).isoformat(), *result]
                rows.append(row)
                print(f'[{index}/{len(planned)}] VLAN={vlan} IP={ip} {result[0]}', flush=True)
                time.sleep(args.delay)
    except KeyboardInterrupt:
        interrupted = True
        print('\nInterrupted; saving completed hosts.')
    try:
        export(rows, args.output, interrupted)
    except (OSError, ValueError) as exc:
        print(f'Cannot save report: {exc}. Close Excel if the file is open.', file=sys.stderr)
        return 2
    print(f'Saved {len(rows)} results to {Path(args.output).resolve()}')
    return 130 if interrupted else (2 if any(r[4] == 'ERROR' for r in rows) else 0)


if __name__ == '__main__':
    sys.exit(main())
