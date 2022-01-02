import logging

from cryptoprimer.Signatures import Signatures


class Tx:
    sig_util = Signatures()

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.sigs = []
        self.reqd = []

    def add_input(self, from_addr, amount):
        self.inputs.append({"address": from_addr,
                            "amount": amount})
        pass

    def add_output(self, to_addr, amount):
        self.outputs.append({"address": to_addr,
                             "amount": amount})
        pass

    def add_required(self, addr):
        self.reqd.append(addr)
        pass

    def sign(self, private):
        message = self.__gather()
        new_sig = self.sig_util.sign(message, private)
        self.sigs.append(new_sig)

    def __gather(self):
        data = [self.inputs, self.outputs, self.reqd]
        return data

    def is_valid(self):
        """
        this is a doc-text
        :return: boolean indicating if transaction is valid.
        """
        inputQty = 0
        outputQty = 0
        try:
            inputQty = self.__compute_qty(self.inputs)
        except NegativeAmountException:
            logging.warning(f"Input amount is negative: {inputQty}")
            return False
        try:
            outputQty = self.__compute_qty(self.outputs)
        except NegativeAmountException:
            logging.warning(f"Output amount is negative: {outputQty}")
            return False

        if outputQty > inputQty:
            print(f"Output {outputQty} is greater than input {inputQty}.")
            return False

        has_req_sig = self.check_required_signatures()
        has_input_sig = self.check_input_signatures()

        return has_req_sig & has_input_sig

    def __compute_qty(self, list):
        sum = 0
        for i in list:
            qty = i["amount"]
            if qty < 0:
                raise NegativeAmountException()
            sum += qty
        return sum

    def check_required_signatures(self):
        if len(self.reqd) == 0:
            return True

        message = self.__gather()

        for addr in self.reqd:
            found = self.__check_is_signed(addr, message)
            if not found:
                logging.warning("Did not find required signature: " + repr(addr))
                return False

        return True

    def __check_is_signed(self, address, message):
        found = False
        for received_signature in self.sigs:
            result = self.sig_util.verify(message, received_signature, address)
            found = result
            if found:
                break
        return found

    def check_input_signatures(self):
        message = self.__gather()
        for node in self.inputs:
            addr = node["address"]
            amount = node["amount"]
            found = self.__check_is_signed(addr, message)
            if not found:
                logging.warning("Did not find input signature: " + repr(addr))
                return False
        return True


class NegativeAmountException(Exception):
    def __init__(self):
        pass
