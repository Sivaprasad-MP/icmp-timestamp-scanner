import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
import icmp_timestamp as scanner


def reply():
    body = struct.pack('!BBHHHIII', 14, 0, 0, 12, 34, 56, 100, 101)
    body = body[:2] + struct.pack('!H', scanner.checksum(body)) + body[4:]
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack('!H', 40)
    header[9] = 1
    header[12:16] = socket.inet_aton('192.0.2.1')
    return bytes(header) + body


class ScannerTests(unittest.TestCase):
    def parse(self, data, **changes):
        args = dict(source='192.0.2.1', target='192.0.2.1', identifier=12, sequence=34, originate=56)
        args.update(changes)
        return scanner.parse_reply(data, **args)

    def test_packet_and_reply(self):
        self.assertEqual(scanner.checksum(scanner.request(12, 34, 56)), 0)
        self.assertEqual(self.parse(reply()), (100, 101))

    def test_unrelated_and_corrupt_packets(self):
        for changes in [dict(identifier=13), dict(sequence=35), dict(originate=57), dict(source='192.0.2.2')]:
            self.assertIsNone(self.parse(reply(), **changes))
        self.assertIsNone(self.parse(reply()[:-1]))
        damaged = bytearray(reply())
        damaged[-1] ^= 1
        self.assertIsNone(self.parse(bytes(damaged)))

    def test_timeout_and_error(self):
        sock = Mock()
        sock.recvfrom.side_effect = socket.timeout
        result = scanner.probe(sock, '192.0.2.1', 0.01, 2)
        self.assertEqual(result[:2], ('NO_REPLY', 2))
        self.assertEqual(sock.sendto.call_count, 2)
        sock.sendto.side_effect = OSError('send failed')
        self.assertEqual(scanner.probe(sock, '192.0.2.1', 1, 2)[0], 'ERROR')

    def test_scope_validation(self):
        with self.assertRaises(SystemExit):
            scanner.main(['--subnet', '10.0.0.0/8', '--dry-run'])
        self.assertEqual(scanner.main(['--ip', '192.0.2.1', '--dry-run']), 0)

    def test_excel_summary_and_text(self):
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.xlsx'
            row = ['=1+1', '192.0.2.1/32', '192.0.2.1', 'UTC', 'EXPOSED', 1, 2, 3, 4, 5, 'reply']
            scanner.export([row], path, interrupted=True)
            book = load_workbook(path)
            self.assertEqual(book['Results']['A2'].data_type, 's')
            self.assertEqual(book['VLAN Summary']['C2'].value, 1)
            self.assertIn('partial', book['Scan Notes']['B2'].value)
            book.close()


if __name__ == '__main__':
    unittest.main()
