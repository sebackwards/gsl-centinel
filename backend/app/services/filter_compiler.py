ALLOWED_FIELDS = {
    "config_id",
    "config_name",
    "event_type",
    "ticket_key",
    "status",
}

ALLOWED_OPS = {"eq", "contains", "starts_with"}


def validate_filter_spec(filters: list[dict]) -> None:
    seen: dict[str, str] = {}
    for entry in filters:
        field = entry.get("field")
        op = entry.get("op")
        if field not in ALLOWED_FIELDS:
            raise ValueError("unsupported field")
        seen[field] = op
    for field, op in seen.items():
        if op not in ALLOWED_OPS:
            raise ValueError("unsupported operator")


def compile_filter_spec(filters: list[dict]) -> dict:
    query: dict = {}
    for entry in filters:
        field = entry.get("field")
        op = entry.get("op")
        value = entry.get("value")
        if field not in query:
            if op == "eq":
                query[field] = value
            elif op == "contains":
                query[field] = {"$regex": f".*{value}.*"}
            elif op == "starts_with":
                query[field] = {"$regex": f"^{value}"}
            elif op == "matches":
                query[field] = {"$regex": value}
    return query
