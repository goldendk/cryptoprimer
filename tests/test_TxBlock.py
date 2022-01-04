import pickle
from unittest import TestCase

from cryptoprimer.Signatures import Signatures
from cryptoprimer.Transaction import Tx


class TestTxBlock(TestCase):
    sig_util = Signatures()
    pr1, pu1 = sig_util.generate_keys()
    pr2, pu2 = sig_util.generate_keys()
    pr3, pu3 = sig_util.generate_keys()
    pr4, pu4 = sig_util.generate_keys()

    def test_save_and_load_transaction_to_file(self):
        tx = Tx()
        tx.add_input(self.pu1, 1)
        tx.add_output(self.pu2, 1)
        tx.sign(self.pr1)

        self.assertTrue(tx.is_valid(), "Should Be valid")

        message = b"some text"

        sig = self.sig_util.sign(message, self.pr1)

        save_file = open("save.dat", "wb")

        pickle.dump(tx, save_file)

        save_file.close()

        load_file = open("save.dat", "rb")

        new_tx = pickle.load(load_file)

        load_file.close()

        self.assertTrue(new_tx.is_valid(), "Loaded transaction should be valid")
