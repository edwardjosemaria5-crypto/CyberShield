"""Rules for the infrastructure location module.

Deliberately minimal by design (v1.1): this is an informational module. It
has NO penalties, NO verdicts and NO findings of severity beyond ``info`` —
the module is excluded from risk scoring by its absence from
``MODULE_WEIGHTS``, so the scorer skips it entirely and neither the Trust
Score, the verdict, nor any other module's result can be affected.
"""

MODULE_NAME = "infrastructure"

#: Module result confidence in every state. Display-only: the module has no
#: weight, so this value never participates in score or confidence
#: aggregation.
DEFAULT_CONFIDENCE = 100

#: Upper bound for any single provider-supplied string after normalization.
#: Mirrors ``_MAX_EVIDENCE_LEN`` in the VirusTotal adapter so the report can
#: never render an unbounded blob.
MAX_FIELD_LEN = 80

#: Provider slug matched against ``INFRASTRUCTURE_PROVIDER`` to select the
#: IPWHOIS (ipwho.is) adapter. Keyless, HTTPS, IP-literal only, 1,000
#: requests/day free with commercial use permitted.
PROVIDER_IPWHOIS = "ipwhois"
