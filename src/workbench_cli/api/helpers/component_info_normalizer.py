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
    "copyright",
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
        # Map alternative field names to our canonical keys
        "license": "license_identifier",  # some API versions use generic 'license'
        "licenseId": "license_identifier",  # camel-cased variant
        "license_id": "license_identifier",  # snake_cased variant
        "licenseName": "license_name",
        "license_name": "license_name",  # ensure canonical form if already correct
    }
    for old, new in aliases.items():
        if old in raw and new not in raw:
            raw[new] = raw.pop(old)

    # When only identifier or name supplied, attempt to set the other for completeness
    if "license_identifier" in raw and "license_name" not in raw:
        raw["license_name"] = raw["license_identifier"]
    if "license_name" in raw and "license_identifier" not in raw:
        raw["license_identifier"] = raw["license_name"]

    # Extract from *licenses* list (Workbench 25.x) when canonical keys still missing
    if ("license_identifier" not in raw or not raw["license_identifier"]) and "licenses" in raw:
        lic_data = raw.get("licenses") or []
        if isinstance(lic_data, list) and lic_data:
            first_lic = lic_data[0]
            if isinstance(first_lic, dict):
                raw["license_identifier"] = first_lic.get("identifier") or first_lic.get("id") or raw.get("license_identifier")
                raw["license_name"] = first_lic.get("name") or raw.get("license_name")
        elif isinstance(lic_data, dict):  # single object
            raw["license_identifier"] = lic_data.get("identifier") or lic_data.get("id") or raw.get("license_identifier")
            raw["license_name"] = lic_data.get("name") or raw.get("license_name")

    # 3. Return only expected fields (others are ignored to shield callers)
    return {field: raw.get(field) for field in _EXPECTED_FIELDS if field in raw} 