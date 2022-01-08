import logging
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptoprimer import Settings
from cryptoprimer.BlockChain import Block


class TxBlock(Block):
    nonce = "AAAAAAA"

    def __init__(self, previousBlock):
        super(TxBlock, self).__init__([], previousBlock)

    def add_tx(self, tx_in):
        self.data.append(tx_in)

    def __count_totals(self):
        total_in = 0
        total_out = 0

        for tx in self.data:
            for addr, amount in tx.inputs:
                total_in += amount
            for addr, amount in tx.outputs:
                total_out += amount

        return total_in, total_out

    def is_valid(self):
        if not super(TxBlock, self).is_valid():
            logging.warning("Parent block is not valid.")
            return False
        for tx in self.data:
            if not tx.is_valid():
                logging.warning("Transaction in data not valid " + str(tx))
                return False
        total_in, total_out = self.__count_totals()
        max_allowed_out = total_in + Settings.MAX_MINING_REWARD
        if total_out - max_allowed_out > 0.000000000001:
            logging.warning(f"bTotal out is greater than allowed: {total_out} > {max_allowed_out}")
            return False
        return True

    def good_nonce(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data), "utf8"))
        digest.update(bytes(str(self.prevHash), "utf8"))
        digest.update(bytes(str(self.nonce), 'utf8'))
        the_hash = digest.finalize()
        if the_hash[:Settings.LEADING_ZEROS] != bytes(''.join(['\x4f' for i in range(Settings.LEADING_ZEROS)]), 'utf8'):
            return False
        return int(the_hash[Settings.LEADING_ZEROS]) < Settings.MAX_NEXT_CHAR

    def find_nonce(self):
        for i in range(1000000):
            self.nonce = ''.join([
                   chr(random.randint(0,255)) for i in range(10*Settings.LEADING_ZEROS)])
            if self.good_nonce():
                return self.nonce
        return None

