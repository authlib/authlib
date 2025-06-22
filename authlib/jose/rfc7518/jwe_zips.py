import zlib

from ..rfc7516 import JsonWebEncryption
from ..rfc7516 import JWEZipAlgorithm


class DeflateZipAlgorithm(JWEZipAlgorithm):
    name = "DEF"
    description = "DEFLATE"

    def compress(self, s):
        """Compress bytes data with DEFLATE algorithm."""
        data = zlib.compress(s)
        # drop gzip headers and tail
        return data[2:-4]

    def decompress(self, s):
        """Decompress DEFLATE bytes data."""
        return zlib.decompress(s, -zlib.MAX_WBITS)


def register_jwe_rfc7518():
    JsonWebEncryption.register_algorithm(DeflateZipAlgorithm())
