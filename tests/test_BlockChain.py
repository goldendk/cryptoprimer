from unittest import TestCase

from cryptoprimer.BlockChain import Block, SomeClass


class TestBlockChain(TestCase):
    root = Block(b'I am root', None)
    B1 = Block('Im a child!', root)
    B2 = Block('Im a brother', root)
    B3 = Block(b'I contiain bytes', B1)
    B4 = Block(12354, B3)
    B5 = Block(SomeClass('Hi there!'), B4)
    B6 = Block("child of B5", B5)

    all_blocks = [B1, B2, B3, B4, B5, B6]

    def test_compute_hash(self):
        for b in self.all_blocks:
            self.assertEqual(b.prevBlock.compute_hash(), b.prevHash)

    def test_tampering(self):
        # Tampering
        self.B4.data = 12345

        self.assertFalse(self.B5.prevBlock.compute_hash() == self.B5.prevHash, "ERROR! Failed to detect tamper")
        self.B5.data.num = 23678

        self.assertFalse(self.B6.prevBlock.compute_hash() == self.B6.prevHash, "ERROR! Failed to detect tamper")
