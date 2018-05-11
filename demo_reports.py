"""
<Name>
  demo_reports.py

<Author>
  Lukas Puehringer <luk.puehringer@gmail.com>

<Started>
  May, 2018

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Generate demo DMARC aggregate reports for three domains, i.e. "your" domain
  and two "foreign" domains, which makes four daily report exchanges, i.e. two
  that you send (outgoing) and two that you receive (incoming) per day, over a
  whole year (2017).

  Although the script was written for a specific purpose, it should be very
  easy to tweak the hardcoded parameters to generate demo data that fits other
  use cases (see `main` function below).

"""
import os
import csv
import random
import socket
import struct
from datetime import datetime, timedelta

from rua import generate_report, validate_report


def get_report_days(start_day, num_days):
  """Get a list of `num_days` days starting at `start_day`. """
  return [start_day + timedelta(days=i) for i in range(0, num_days)]


def get_report_metadata(reporter, reportee, day, **kw):
  """Return "report_metadata" part using passed `reporter` and `reportee`
  domain and `day` for which the report aggregates results. """
  # Get unix timestamp for begin of day
  begin = int(day.date().strftime("%s"))
  # Get unix timestamp for end of day, i.e. being + 1 day - 1 second
  end = begin + 86400 - 1

  return {
    "org_name": reporter,
    "org_email": "postmaster@{domain}".format(domain=reporter),
    "extra_contact_info": "www.{domain}".format(domain=reporter),
    # "<report receiver domain>:<non-leap seconds since epoch>"
    "report_id": "{reportee}:{ts}".format(reportee=reportee, ts=end),
    # The time range in UTC covered by messages in this report,
    # specified in seconds since epoch
    "date_range": {
      "begin": begin,
      "end": end
    }
  }


def get_policy_published(reportee, policy, **kw):
  """Return "policy_published" part for a passed `reportee` and `policy`. For
  now we use the hardcoded values for `adkim`, `aspf` and `pct` everywhere. """
  return {
    "domain": reportee,
    "adkim": "r",
    "aspf": "r",
    "p": policy,
    "sp": policy,
    "pct": 100
  }


def get_row(reportee, policy, dkim_result, spf_result, message_count,
      source_ip, **kw):
  """Return "row" part based on `reportee`, `policy`, `dkim_result` and
  `spf_result`, `message_count` and `source_ip`. See inline comments for more
  information on how some of the values are populated. """
  # Aligned DKIM and SPF result can only "pass" if one  of the corresponding
  # raw results passes. However, even if a raw result "passes" the aligned
  # result can still "fail". For now we always only have one or no raw result
  # for DKIM and one for SPF and we always let alignment always pass.
  aligned_dkim_result = "pass" if dkim_result == "pass" else "fail"
  aligned_spf_result  = "pass" if spf_result == "pass" else "fail"

  # Disposition is based on policy and aligned DMARC result. If DMARC passes,
  # i.e. one of aligned DKIM or SPF passes, disposition is none, else we apply
  # the published policy.
  if (aligned_dkim_result == "pass" or aligned_spf_result == "pass"):
    disposition = "none"

  else:
    disposition = policy

  return {
    "source_ip": source_ip,
    "count": message_count,
    "policy_evaluated": {
      "disposition": disposition,
      "dkim": aligned_dkim_result,
      "spf": aligned_spf_result,
    }
  }


def get_identifiers(reporter, reportee, **kw):
  """Return "identifiers" part. For now, the `envelope_to` field always
  corresponds to the `reporter`, i.e. mail receiver and the `header_from` to
  the `reportee`, i.e. purported mail sender. """
  return {
    "envelope_to": reporter,
    "header_from": reportee
  }

def get_auth_results(reportee, dkim_result, spf_result, **kw):
  """Return "auth_results" part. This can be no or more raw DKIM results and
  one or more SPF results. For now we always return either no or one DKIM and
  one SPF result, based on the passed `dkim_result` and `spf_result` and use
  only the `reportee` domain. """
  dkim = []
  if dkim_result:
    dkim.append({
    "domain": reportee,
    "result": dkim_result,
  })

  spf = [{
    "domain": reportee,
    "result": spf_result
  }]

  return {
    "dkim": dkim,
    "spf": spf
  }


def get_record(**kw):
  """Return "record" part. A report can have multiple records, each record
  aggregates over a mail sender IP and an evaluated policy. For now we generate
  one record per report. """
  return {
    "row": get_row(**kw),
    "identifiers": get_identifiers(**kw),
    "auth_results": get_auth_results(**kw),
  }


def get_report_data(**kw):
  """Get report data for a single report. """
  return {
    "report_metadata": get_report_metadata(**kw),
    "policy_published": get_policy_published(**kw),
    "records": [get_record(**kw)]
  }


def get_country_to_ip_dict():
  """Read IPv4 csv file with two columns "IP number" and "two letter country
  code", and create a dictionary with country codes as keys and IP addresses as
  values. """
  ip_to_country_dict = {}
  with open("ipv4_to_country.csv") as fp:
    csv_reader = csv.reader(fp, delimiter=",")
    for row in csv_reader:
      # Ignore empty and commented lines
      if len(row) and not row[0].startswith("#"):
        # Convert IP number to string
        ip_string = socket.inet_ntoa(struct.pack('!L', int(row[0])))
        ip_to_country_dict[row[1]] = ip_string

  return ip_to_country_dict


def main():
  """Generate 4 valid daily demo DMARC aggregate reports over the course of a
  year and write them to files using the typical name format. """
  # Configure the random seed with a randomly chosen number for reproducibility
  random.seed(13)

  # Paths (names) to store report to
  base_path = "reports"
  incoming_path = os.path.join(base_path, "incoming")
  outgoing_path = os.path.join(base_path, "outgoing")

  # Create output dirs if not there
  if not os.path.exists(incoming_path):
    os.makedirs(incoming_path)

  if not os.path.exists(outgoing_path):
    os.makedirs(outgoing_path)

  # Load IP data from csv
  ip_data = get_country_to_ip_dict()

  # Available raw DKIM and SPF results to choose from randomly. A DKIM result
  # of type `None` means that the report has no raw DKIM result.
  dkim_result_choices = [None, "none", "pass", "fail", "policy", "neutral",
      "temperror", "permerror"]
  spf_result_choices = ["none", "neutral", "pass", "fail", "softfail",
      "temperror", "permerror"]

  # Time range to create reports for
  start_day = datetime(2017, 1, 1)
  num_days = 365

  # Bounds for random message count
  message_count_min = 0
  message_count_max = 100

  # Domain variables
  # NOTE: Top-level domain must be a 2-letter country code because it is used
  # to determine a legitimate IP address from the corresponding country block
  my_domain = "demo-me.at"
  foreign_domain_1 = "demo-abc.us"
  foreign_domain_2 = "demo-xyz.de"

  # Define four report exchanges between my domain and two foreign domains,
  # i.e. foreign domains each send reports to and receive reports from me.
  report_vars_list = [
    # Incoming reports
    {
      "reporter": foreign_domain_1,
      "reportee": my_domain,
      "policy": "none",
    },
    {
      "reporter": foreign_domain_2,
      "reportee": my_domain,
      "policy": "none",
    },
    # Outgoing reports
    {
      "reporter": my_domain,
      "reportee": foreign_domain_1,
      "policy": "quarantine",
    },
    {
      "reporter": my_domain,
      "reportee": foreign_domain_2,
      "policy": "reject",
    }
  ]

  # Iterate over 3 sets of basic report data one for incoming and one for
  # outgoing reports ...
  for report_vars in report_vars_list:
    # ... create a report for each day using random values
    for day in get_report_days(start_day, num_days):
      report_vars["day"] = day

      # Randomly choose raw dkim and spf result and message count
      report_vars["dkim_result"] = random.choice(dkim_result_choices)
      report_vars["spf_result"] = random.choice(spf_result_choices)
      report_vars["message_count"] = random.randint(message_count_min,
          message_count_max)

      # Assign IP address based on SPF result
      if report_vars["spf_result"] == "pass":
        # Use tld of reportee domain to choose a legitimate email
        country_code = report_vars["reportee"].split(".")[-1].upper()
        report_vars["source_ip"] = ip_data[country_code]

      else:
        report_vars["source_ip"] = random.choice(ip_data.values())

      # Genrate report data
      report_data = get_report_data(**report_vars)

      # Generate DMARC compliant report
      report_xml_string, report_name = generate_report(report_data)

      # Validate report schema
      validate_report(report_xml_string)

      # Store incoming and outgoing reports to different dirs
      base_path = (outgoing_path
          if report_vars["reporter"] == my_domain else incoming_path)

      # Write report to file
      with open(os.path.join(base_path, report_name), "w") as fp:
        fp.write(report_xml_string)


if __name__ == "__main__":
  main()
