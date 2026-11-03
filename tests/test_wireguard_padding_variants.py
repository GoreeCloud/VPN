"""Every unused Base64 padding-bit variant must be rejected as a peer identity."""

import base64
import unittest

from goreecloud_vpn.core import ValidationError, check_key


class WireGuardPaddingVariantTests(unittest.TestCase):
    def test_all_three_noncanonical_variants_of_each_key(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for seed in (1, 127, 255):
            raw = bytes([seed]) * 32
            canonical = base64.b64encode(raw).decode("ascii")
            self.assertEqual(check_key(canonical), canonical)
            final_sextet = alphabet.index(canonical[-2])
            self.assertEqual(final_sextet & 3, 0)
            for unused_bits in (1, 2, 3):
                alternate = canonical[:-2] + alphabet[final_sextet | unused_bits] + "="
                with self.subTest(seed=seed, unused_bits=unused_bits):
                    self.assertNotEqual(alternate, canonical)
                    self.assertEqual(base64.b64decode(alternate, validate=True), raw)
                    with self.assertRaises(ValidationError):
                        check_key(alternate)

    def test_wrong_padding_and_non_base64_are_rejected(self):
        canonical = base64.b64encode(bytes(range(1, 33))).decode("ascii")
        for value in (canonical[:-1] + "A", canonical[:-1] + " ", canonical[:-1]):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                check_key(value)


if __name__ == "__main__":
    unittest.main()
