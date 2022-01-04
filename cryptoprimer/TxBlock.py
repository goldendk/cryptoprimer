import logging

from cryptoprimer.BlockChain import Block


class TxBlock(Block):

    def __init__(self, previousBlock):
        super(TxBlock, self).__init__([], previousBlock)

    def add_tx(self, tx_in):
        self.data.append(tx_in)
        pass
    def is_valid(self):
        if not super(TxBlock, self).is_valid():
            logging.warning("Parent block is not valid.")
            return False
        for tx in self.data:
            if not tx.is_valid():
                logging.warning("Transaction in data not valid " + str(tx))
                return False
        return True
