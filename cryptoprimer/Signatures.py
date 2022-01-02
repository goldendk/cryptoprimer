from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class Signatures:
    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key, private_key.public_key()

    def sign(self, message, private):
        inner_message = bytes(str(message), 'utf-8')
        sig = private.sign(inner_message,
                           padding.PSS(
                               mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=padding.PSS.MAX_LENGTH
                           ),
                           hashes.SHA256())
        return sig

    def verify(self, message, signature, public):
        inner_message = bytes(str(message), 'utf-8')
        try:
            public.verify(
                signature,
                inner_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256())
            return True
        except InvalidSignature:
            return False
