from unittest import TestCase

from cryptoprimer.Signatures import Signatures
from cryptoprimer.Transaction import Tx


class TestTx(TestCase):
    signatures = Signatures()
    pr1, pu1 = signatures.generate_keys()
    pr2, pu2 = signatures.generate_keys()
    pr3, pu3 = signatures.generate_keys()
    pr4, pu4 = signatures.generate_keys()

    # Valid transactions.
    def test_basic_transaction(self):
        Tx1 = Tx()
        Tx1.add_input(self.pu1, 1)
        Tx1.add_output(self.pu2, 1)
        Tx1.sign(self.pr1)
        self.assertTrue(Tx1.is_valid(), "Transaction should be valid after being signed with pr1")

    def test_multiple_outputs(self):
        Tx2 = Tx()
        Tx2.add_input(self.pu1, 2)
        Tx2.add_output(self.pu2, 1)
        Tx2.add_output(self.pu2, 1)
        Tx2.sign(self.pr1)

        self.assertTrue(Tx2.is_valid(), "Tx2 should be valid after signing by '1'")

    def test_escrow_transaction(self):
        # '3' is sending 1.1 coins to '1' and needs signature by escrow party '4'
        _tx = Tx()
        _tx.add_input(self.pu3, 1.2)
        _tx.add_output(self.pu1, 1.1)
        _tx.add_required(self.pu4)
        _tx.sign(self.pr3)  # the sender
        _tx.sign(self.pr4)  # the 'esgrove' signature.
        self.assertTrue(_tx.is_valid())

    # invalid transactions.

    # '2' is attempting to send one of '1''s coins to himself.
    def test_sign_with_wrong_key(self):
        tx = Tx()
        tx.add_input(self.pu1, 1)
        tx.add_output(self.pu2, 1)
        tx.sign(self.pr2)
        self.assertFalse(tx.is_valid(), "Should be signed by '1' and not any other to be valid.")

    # two input addresses (3,4) sending to one receiver (1), but only one sender signs.
    def test_two_input_addr_but_only_one_signs(self):
        tx = Tx()
        tx.add_input(self.pu3, 1)
        tx.add_input(self.pu4, .1)
        tx.add_output(self.pu1, 1.1)
        tx.sign(self.pr3)
        self.assertFalse(tx.is_valid(), "Should be signed by '1' and not any other to be valid.")

    # '4' is trying to send more coins to (1 and 2) than he put into the transaction.
    #def test_output_exceeds_input(self):
    #    tx = Tx()
    #    tx.add_input(self.pu4, 1.2)
    #    tx.add_output(self.pu1, 1)
    #    tx.add_output(self.pu2, 2)
    #    tx.sign(self.pr4)
    #    self.assertFalse(tx.is_valid(), "Output higher than input should not be allowed.")

    def test_negative_not_allowed(self):
        tx = Tx()
        tx.add_input(self.pu2, -1)
        tx.add_output(self.pu1, -1)
        tx.sign(self.pr2)

        self.assertFalse(tx.is_valid(), "Negative values should not be allowed.")

    def test_modified_tx(self):
        tx = Tx()
        tx.add_input(self.pu1, 1)
        tx.add_output(self.pu2, 1)
        tx.sign(self.pr1)
        tx.outputs[0] = self.pu3  # changed transaction should not validate.

        self.assertFalse(tx.is_valid(), "Changed transactions after signing should not validate.")
