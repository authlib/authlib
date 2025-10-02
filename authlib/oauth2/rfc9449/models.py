class AuthorizationCodeMixin:
    def get_dpop_jkt(self):
        """A method to get the DPoP jkt associated with this code:

        .. code-block::

            def get_dpop_jkt(self):
                return self.dpop_jkt
        """
        return None


class TokenMixin:
    def get_dpop_jkt(self):
        """A method to get the DPoP jkt associated with this token:

        .. code-block::

            def get_dpop_jkt(self):
                return self.dpop_jkt
        """
        return None