.. _frameworks_clients:

Custom Claims Class
=================
Since Authlib 1.5.2 there is the functionality to pass a custom claims class to authorize_access_token.

This documentation demonstrates this feature by covering the special use case of authenticating with ORCID, a popular academic identity provider.

ORCID has a non-standard response in the "amr" claim that returns a single string, rather than a list. Given the popularity of ORCID, this document specifies how to resolve this.

Example: Log In with ORCID
---------------------
To do so, create a custom claims class::

	from authlib.jose.errors import InvalidClaimError
	from authlib.oidc.core import CodeIDToken

	class ORCIDHandledToken(CodeIDToken):
	    def validate_amr(self):
	        """OPTIONAL. Authentication Methods References. JSON array of strings
	        that are identifiers for authentication methods used in the
	        authentication. For instance, values might indicate that both password
	        and OTP authentication methods were used. The definition of particular
	        values to be used in the amr Claim is beyond the scope of this
	        specification. Parties using this claim will need to agree upon the
	        meanings of the values used, which may be context-specific. The amr
	        value is an array of case sensitive strings. However, ORCID sends
	        just a string back and this causes a validation error. This patched
	        version fixes it.
	        """
	        amr = self.get("amr")
	        if amr and not isinstance(self["amr"], list | str):
	            claim_error = "amr"
	            raise InvalidClaimError(claim_error)


Then, when fetching your token in the framework of your choice, pass your custom class::

	token = oauth.cilogon.authorize_access_token(
	            request, claims_cls=ORCIDHandledToken
	        )

The only difference to the original is the addition of the "| str" check which allows for lists and strings in the "amr" claim.

See the underlying `IDToken code <https://github.com/authlib/authlib/blob/main/authlib/oidc/core/claims.py>`_ to determine which methods you can override.