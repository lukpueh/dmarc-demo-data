# DMARC Aggregate Reports

A Python/Jinja2-based DMARC aggregate report generator and validator ([`schema
version 0.1`](https://dmarc.org//dmarc-xml/0.1/rua.xsd)).

The repo also provides a script to generate DMARC aggregate reports for demo
purposes, with half-sensible random values, including options to generate
sender IP addresses based on countries.


# Installation
```shell
git clone https://github.com/lukpueh/dmarc-demo-data
cd dmarc-demo-data
# TIP: Use virtual environments
pip install -r requirements.txt
```


# Report Generation And Validation Example
Use the following Python snippet to generate, validate and store a single DMARC
aggregate report under its corresponding name, using sample data. See
[`data.sample_report`](data.py) to learn more about the dictionary structure
required by `generate_report`.

```python
from rua import generate_report, validate_report
from data import sample_report

# Generate a DMARC aggregate report passing it some sample data
report, report_name = generate_report(sample_report)

# Verify that report follows the right schema.
validate_report(report)

# Write to file using the typical report filename format
with open(report_name, "w") as f:
  f.write(report)
```


# Demo Data Generation

Run the following script to generate some opinionated demo DMARC aggregate
reports for three domains, i.e. "your" domain and two foreign domains, which
makes four daily report exchanges, i.e. two that you send and two that
you receive, over the year 2017.

Although the script was written for a specific purpose, it should be very easy
to tweak the hardcoded parameters to generate demo data that fits other use
cases (see [`demo_reports.main`](demo.py)


```shell
# Writes reports to `reports/incoming` and `reports/outgoing`
python demo_reports.py
```
