from unittest import TestCase

from cryptoprimer.Signatures import Signatures


class TestSignatures(TestCase):
    uut = Signatures()

    def test_generate_keys(self):
        pri, pub = self.uut.generate_keys()
        self.assertIsNotNone(pri, "private should not be empty")
        self.assertIsNotNone(pub, "private should not be empty")

    def test_sign_and_verify(self):
        pr, pu = self.uut.generate_keys()
        message = b"This is a secret message"
        sig = self.uut.sign(message, pr)
        correct = self.uut.verify(message, sig, pu)
        self.assertTrue(correct, "Verify should be true for message, signature and public key")

