"""The rules about WHAT may be asked for and WHY. This is purpose limitation and data minimisation in code.
A company must name a purpose and ONE field, and the purpose must allow that field."""

# purpose code -> readable name and the fields that purpose may ask for
PURPOSES = {
    "DELIVERY": {"label": "delivery", "fields": ["address", "name", "phone"]},
    "KYC": {"label": "identity check", "fields": ["address", "name"]},
    "CONSULTATION": {"label": "medical consultation", "fields": ["blood_group", "name"]},
}
FIELDS = {"address", "blood_group", "name", "phone"}      # the only fields that can ever be asked for
MIN_DURATION_SEC = 30
MAX_DURATION_SEC = 86_400
MAX_VALUE_CHARS = 2_000                                      # a returned value is a short fact, never a document


def purpose_allows(purpose: str, field: str) -> bool:
    return field in PURPOSES.get(purpose, {}).get("fields", [])
