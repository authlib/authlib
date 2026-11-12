Fixed
~~~~~

- The order of the values of a ``response_type`` does not matter anymore, per
  RFC 6749 §3.1.1. This applies to the ``RESPONSE_TYPES`` of the grants, to
  the ``response_types`` of the SQLAlchemy client mixin, and to
  ``get_claim_cls_by_response_type``. :pr:`982`
