import csv
import io


def encode_row(values):
    """Encode one CSV row without a trailing newline."""
    output = io.StringIO()
    csv.writer(output, lineterminator="").writerow(values)
    return output.getvalue()
