Implemented the minimal CSV repair in [src/exporter.py](after/src/exporter.py).

Evidence:

- `python3 -m unittest discover -s tests -p 'test_exporter.py' -v`
- `Ran 1 test ... OK`
- Only `src/exporter.py` was edited.

Remaining uncertainty: broader tests were not run, per authorization.
