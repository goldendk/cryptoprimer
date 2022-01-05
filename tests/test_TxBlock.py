import pickle
from unittest import TestCase

from cryptoprimer.Signatures import Signatures
from cryptoprimer.Transaction import Tx
from cryptoprimer.TxBlock import TxBlock


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

        root = TxBlock(None)
        root.add_tx(tx)

        tx2 = Tx()
        # pu2 sends pu3 1 coin. 0.1 coins is a fee to the network.
        tx2.add_input(self.pu2, 1.1)
        tx2.add_output(self.pu3, 1)
        tx2.sign(self.pr2)

        root.add_tx(tx2)

        block = TxBlock(root)

        tx3 = Tx()
        # pu3 sends pu1 1 coin. 0.1 coins is a fee to the network.
        tx3.add_input(self.pu3, 1.1)
        tx3.add_output(self.pu1, 1)
        tx3.sign(self.pr3)
        block.add_tx(tx3)

        tx4 = Tx()
        # pu1 sends 1 coin to pu2 with pu3 as escrow.
        tx4.add_input(self.pu1, 1)
        tx4.add_output(self.pu2, 1)
        tx4.add_required(self.pu3)
        tx4.sign(self.pr1)
        tx4.sign(self.pr3)
        block.add_tx(tx4)

        self.assertTrue(block.is_valid(), "Block should be valid.")

        self.assertTrue(root.is_valid(), "Root should be valid.")

        # save and load the file.
        save_file = open("block.dat", "wb")
        pickle.dump(block, save_file)
        save_file.close()
        load_file = open("block.dat", "rb")
        load_block = pickle.load(load_file)
        load_file.close()
        print(bytes(str(load_block.data), 'utf8'))
        self.assertTrue(load_block.is_valid(), "Loaded block should still be valid.")

        for b in [root, block, load_block, load_block.prevBlock]:
            self.assertTrue(b.is_valid(), "Not valid, but should be : " + repr(b))

        block2 = TxBlock(block)
        tx = Tx()

        tx.add_input(self.pu3, 1)
        tx.add_output(self.pu1, 100)
        tx.sign(self.pr3)

        not_valid_tx = Tx()
        not_valid_tx.add_input(self.pu3, 1)
        not_valid_tx.add_output(self.pu1, 100) #definately not allowed.
        not_valid_tx.sign(self.pr3)
        block2.add_tx(not_valid_tx)

        load_block.prevBlock.add_tx(tx4)

        for b in [block2, load_block]:
            self.assertFalse(b.is_valid(), "Should not be valid due to tampering.")







