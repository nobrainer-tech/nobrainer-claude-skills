def encode_row(values):
    """Encode one CSV row without a trailing newline."""
    return ",".join(str(value) for value in values)
