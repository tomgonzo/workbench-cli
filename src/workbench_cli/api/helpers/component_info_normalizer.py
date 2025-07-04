from typing import Any, Dict, List

# Fields that callers actively use; expand if more become important.
_EXPECTED_FIELDS = {
    "id",
    "cpe",
    "name",
    "version",
    "purl",
    "purl_type",
    "purl_namespace",
    "purl_name",
    "purl_version",
    "supplier_name",
    "supplier_url",
    "license_identifier",
    "license_name",
    "comment",
}


def normalize_component_response(raw: Any) -> Dict[str, Any]:
    """Return a stable dict from the Workbench *components/get_information* response.

    Workbench 25.x sometimes returns the *data* field as a single-element list, or
    as a dict.  Future versions may rename or add keys.  This helper:
      • Converts list→dict when length==1.
      • Ignores unknown fields (passes through only those we care about).
      • Returns an empty dict on unexpected structures.
    """
    # 1. Normalise list ↔ dict
    if isinstance(raw, list):
        raw = raw[0] if raw else {}
    if not isinstance(raw, dict):
        return {}

    # 2. Map any known aliases between versions (none yet, but placeholder)
    aliases = {
        # "licenseId": "license_id",  # example if it appears in another version
    }
    for old, new in aliases.items():
        if old in raw and new not in raw:
            raw[new] = raw.pop(old)

    # 3. Return only expected fields (others are ignored to shield callers)
    return {field: raw.get(field) for field in _EXPECTED_FIELDS if field in raw} 