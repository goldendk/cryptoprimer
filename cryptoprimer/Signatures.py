from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


class Signatures:
    def generate_keys(self):
        """
        Generate SSH keys of length 2048
        :return: the serialized version of the keys.
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self.__serialize_private_key(private_key), self.__serialize_public_key(private_key.public_key())

    def sign(self, message, private_ser):
        """

        :param message: the message to sign
        :param private_ser: the serialized private key
        :return: The signed message (after hashing).
        """
        inner_message = bytes(str(message), 'utf-8')
        private = self.__deserialize_private_key(private_ser)
        sig = private.sign(inner_message,
                           padding.PSS(
                               mgf=padding.MGF1(hashes.SHA256()),
                               salt_length=padding.PSS.MAX_LENGTH
                           ),
                           hashes.SHA256())
        return sig

    def verify(self, message, signature, public_ser):
        """
        Verify that a public sighed the given message.
        :param message: the message to verify.
        :param signature:  the given signature
        :param public_ser: the public key that is claimed to have signed the message.
        :return: Boolean indicating if the message is signed by the provided public key.
        """
        inner_message = bytes(str(message), 'utf-8')
        try:
            public = self.__deserialize_public_key(public_ser)
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

    # ############## Serialization methods ######################

    def __serialize_public_key(self, public):
        pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    def __deserialize_public_key(self, key_text):
        public_key = serialization.load_pem_public_key(key_text)
        return public_key

    def __serialize_private_key(self, private):
        pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    def __deserialize_private_key(self, key_text):
        private_key = serialization.load_pem_private_key(
            key_text,
            password=None,
        )
        return private_key

    # ###########################################################
