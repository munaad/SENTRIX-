# SENTRIX

SENTRIX is a local only static analysis tool for detecting security issues in source code. It was built to demonstrate how vulnerability detection can be implemented using Python AST parsing and rule based pattern matching without relying on external security scanners or cloud services.


## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5050` 

## Side Notes

- The findings are currently scored primarily by severity and count, not by deployment context.
  For example, a hardcoded credential in a test/demo snippet may score similarly to one in production auth logic.
  A future improvement would be contextual risk weighting based on file location, application role, and data sensitivity.



