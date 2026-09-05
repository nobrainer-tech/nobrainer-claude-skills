import unittest

from src.exporter import encode_row


class EncodeRowTest(unittest.TestCase):
    def test_quotes_commas_and_empty_trailing_column(self):
        self.assertEqual(
            encode_row(["plain", "ACME, Inc.", 'said "yes"', ""]),
            'plain,"ACME, Inc.","said ""yes""",',
        )


if __name__ == "__main__":
    unittest.main()
