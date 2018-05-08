# DMARC demo data

Methods to generate and validate XML formatted DMARC aggregate reports.

# Installation
```shell
git clone https://github.com/lukpueh/dmarc-demo-data
cd dmarc-demo-data
pip install -r requirements.txt
```

# Example Usage
The following snippet can be used to generate, validate and store a sample
DMARC aggregate report under its corresponding name using a Python
interpreter.

```python
from rua import generate_report, validate_report
from data import sample_report

# Generate a DMARC aggregate report passing it some sample data
report, report_name = generate_report(sample_report)

# Verify that report follows the right schema
# If no exception is raised we're good
validate_report(report)

# Write to file using the typical filename format
with open(report_name, "w") as f: f.write(report)
```