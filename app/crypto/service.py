def validate_public_key_format(key: str | None) -> bool:
    if not key:
        return False
    return key.strip().startswith("-----BEGIN PUBLIC KEY-----") and key.strip().endswith("-----END PUBLIC KEY-----")
