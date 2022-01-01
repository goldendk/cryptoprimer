from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class SomeClass:
    value = None
    num = 1001

    def __init__(self, stringValue):
        self.value = stringValue

    def __repr__(self):
        return self.value + "---" + str(self.num)


class Block:
    data = None
    prevHash = None
    prevBlock = None

    def __init__(self, data, previousBlock):
        self.data = data

        if previousBlock is not None:
            self.prevBlock = previousBlock
            self.prevHash = previousBlock.compute_hash()
        pass

    def compute_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes(str(self.data), "utf8"))
        digest.update(bytes(str(self.prevHash), "utf8"))
        the_hash = digest.finalize()
        return the_hash
