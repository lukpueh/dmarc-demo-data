"""
<Name>
  rua.py

<Author>
  Lukas Puehringer <luk.puehringer@gmail.com>

<Started>
  May, 2018

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Methods to generate and validate XML formatted DMARC aggregate reports.

  The following snippet can be used to generate, validate and store a sample
  DMARC aggregate report under its corresponding name using a Python
  interpreter

  ```
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

"""
from lxml import etree
from jinja2 import FileSystemLoader, Environment

# Filename constants
REPORT_TEMPLATE_DIR = "."
REPORT_TEMPLATE_NAME = "rua.xml.j2"
REPORT_SCHEMA_NAME = "rua.xsd"

# Prepare DMARC aggregate report template
LOADER = FileSystemLoader(REPORT_TEMPLATE_DIR)
ENV = Environment(loader=LOADER, trim_blocks=True, lstrip_blocks=True)
REPORT_TEMPLATE = ENV.get_template(REPORT_TEMPLATE_NAME)

# Prepare DMARC aggregate report schema
with open(REPORT_SCHEMA_NAME, "r") as f:
  schema_data = f.read()
REPORT_SCHEMA = schema_data

# Define typical filename format for DMARC aggregate reports
REPORT_FILENAME_FORMAT = "{org_name}!{domain}!{begin}!{end}.xml"


def _get_report_filename_from_context(context):
  """Generate report filename from context used with `generate_report`.  """
  return REPORT_FILENAME_FORMAT.format(
      org_name=context["report_metadata"]["org_name"],
      domain=context["policy_published"]["domain"],
      begin=context["report_metadata"]["date_range"]["begin"],
      end=context["report_metadata"]["date_range"]["end"])


def generate_report(context):
  """
  <Purpose>
    Populate DMARC aggregate report based on passed context returning a tuple
    containing report (UTF-8 string) and report name.

  <Arguments>
    context:
            A python dictionary containing DMARC aggregate report data.
            (see data.sample_report for the required format)

  <Returns>
    A tuple containing the generated report as UTF-8 encoded string and the
    report name corresponding to REPORT_FILENAME_FORMAT.

  """
  # Render template using passed context
  report_string = REPORT_TEMPLATE.render(context)

  # Encode as `UTF-8` string (required e.g. by validate functions)
  report_string = report_string.encode("utf-8")

  # Create report name
  report_name = _get_report_filename_from_context(context)

  return report_string, report_name


def validate_report(dmarc_report):
  """
  <Purpose>
    Validate passed DMARC report using REPORT_SCHEMA.

  <Arguments>
    dmarc_report:
            UTF-8 encoded DMARC aggregate report data.

  <Raises>
    ParseError,
            if xml_data can' be parsed.

    InvalidDocument,
            if xml_data is not valid against xsd_data.

  <Returns>
    None.
  """
  validate(dmarc_report, REPORT_SCHEMA)


def validate(xml_data, xsd_data):
  """
  <Purpose>
    Validate passed xml data against xsd data and raise Exception
    if data is invalid.

  <Arguments>
    xml_data:
            UTF-8 encoded XML data to be validated.

    xsd_data:
            UTF-8 encoded XSD schema used for validation.

  <Raises>
    ParseError,
            if xml_data can' be parsed.

    XMLSchemaParseError,
            if xsd_data can't be parsed.

    InvalidDocument,
            if xml_data is not valid against xsd_data.

  <Returns>
    None.

  """
  # Create XML objects from xml and xsd data
  xml = etree.fromstring(xml_data)
  schema_xml = etree.fromstring(xsd_data)

  # Create a schema object from schema xml object
  schema = etree.XMLSchema(schema_xml)

  # Validate
  schema.assertValid(xml)
