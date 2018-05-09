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
  Generate demo reports for the following "DMARC viewer" demo views:


  == (1) Am I DMARC ready? ==
  Show mail sent with my domain by a subset of raw DKIM results (neutral vs.
  temperror vs. permerror) as per incoming aggregate reports. Any other result
  than pass, will make the aligned DKIM result fail.

  == (2) Raw DKIM results ==
  Show how much of the mail sent with my domain fails DMARC checks, based on
  aligned DKIM and SPF results taken from incoming reports, compared to the
  total mail volume. If the DMARC failing portion seems indeed illegitimate, I
  might be ready to add a restrictive DMARC policy (quarantine or reject) to my
  DNS.

  == (3) Who sent me spoofed mail and how did I react? ==
  Show received mail that was purportedly spoofed, i.e. failed aligned DKIM and
  SPF checks (DMARC fail), and mail that I have rejected or placed under
  quarantine, all based on the information taken from outgoing DMARC aggregate
  reports.


  = Parameter deliberations =
  == report_metadata ==
  === org_name, org_email, extra_contact_info ==
   - my domain, e.g.: dmarc-viewer.org (outgoing reports)
   - foreign domain, guugle.com (incoming reports)
   --> manual
  === report_id (time portion), date_range ===
   for my and foreign domain each 7 reports (2018-01-01 - 2018-01-07)
   --> fixed date ranges

  == policy_published ===
   For my and foreign domain each one
   --> manual or via DNS query of, e.g. alexa
  === domain ===
  --> relate with my domain / foreign domain
  === adkim, aspf===
  let's do both "r"
  === p, sp ===
  let's do both none
  === pct ===
  let's do both 100


  == records ===
  let's start with one record

  === row ===
  ==== source_ip ====
  For my and foreign domain each one legitimate and some random ones,
  with legitimate from Austria, and others from anywhere
  --> check if there's something like reverse geoip
  --> relate with result!

  ==== count ====
  Random numbers
  --> maybe within a reasonable range and according to a distribution
  --> maybe relate with result?

  ==== policy evaluated ===
  ===== disposition =====
  Random with of none, quarantine, reject. None if verification passes or
  policy is None, else quarantine or reject
  --> relate with result and policy!

  ===== dkim =====
  Random pass or fail
  --> relate with raw dkim
  --> pass only if raw dkim available and its result is pass # TODO make sure

  ===== spf =====
  Random pass or fail
  --> relate with raw spf
  --> pass only if spf passes (or none??) # TODO find out

  === identifiers ===
  ==== header_from ====
  same as report receiver, i.e. either my or foreign domain
  --> relate with report_metadata, policy_published


  === auth_results ===
  ==== DKIM ====
  Let's start with randomly no or one DKIM
  ===== domain =====
  --> relate with report_metadata, policy_published for passing
  --> maybe some random domains for failing
  ===== result =====
  randomly none, pass, fail, policy, neutral, temperror, permerror

  ==== spf ====
  Let's start with always one
  ===== domain =====
  --> relate with report_metadata, policy_published

  ===== result =====
  randomly none, neutral, pass, fail, softfail, temperror, permerror

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
  """Return report "report_metadata" part using passed `reporter` and
  `reportee` domain and `day` for which the report aggregates results.
  The date range is generated as begin of passed day to end of passed day. End
  of day is also used for the report id. """

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
  """Return report "policy_published" part for a passed `reportee` and `policy`
  For now we use the same hardcoded values for `adkim`, `aspf` and `pct`. """
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
  """Return report "row" part based on `reportee`, `policy`, `dkim_result`
  and `spf_result`, `message_count` and `source_ip`. See inline comments
  for more information on how some of the values are populated. """

  # Aligned DKIM and SPF result can only pass if one (for now we always only
  # have one or no raw result for DKIM and one for SPF) of the corresponding
  # raw results passes, however even if a raw result passes the aligned result
  # can still be fail (for now we say alignment always passes).
  aligned_dkim_result = "pass" if dkim_result == "pass" else "fail"
  aligned_spf_result  = "pass" if spf_result == "pass" else "fail"

  # Disposition is based on policy and aligned DMARC result
  # If DMARC passes, i.e. one of aligned DKIM or SPF passes, disposition is
  # none, else the policy is used
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
  """Return report "identifiers" part.
  For now, the `envelope_to` field always corresponds to the `reporter`, i.e.
  mail receiver and the `header_from` to the `reportee`, i.e. purported mail
  sender. """
  return {
    "envelope_to": reporter,
    "header_from": reportee
  }

def get_auth_results(reportee, dkim_result, spf_result, **kw):
  """Return report "auth_results" part. This can be no or more raw dkim
  results and one or more spf results.
  For now we always return either no or one dkim and one spf result, based
  on the passed dkim_result and spf_result. """
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
  """Return report "record" part. A report can have multilpe records,
  each record aggregates over a mail sender IP and an evaluated policy.
  For now we generate one record per report. """
  return {
    "row": get_row(**kw),
    "identifiers": get_identifiers(**kw),
    "auth_results": get_auth_results(**kw),
  }


def get_report_data(**kw):
  """Get a single report issued by the `reporter` for a given `reportee` on
  a given `day`. """
  return {
    "report_metadata": get_report_metadata(**kw),
    "policy_published": get_policy_published(**kw),
    "records": [get_record(**kw)]
  }


def get_country_to_ip_dict(path):
  """Read a csv file from `path` with two columns "IP number" and "two letter
  country code", and create a dictionary with country codes as keys and
  IP addresses as values.
  Lines starting with "#" are ignored and IP addresses are converted to
  strings. """
  ip_to_country_dict = {}
  with open("ipv4_to_country.csv") as fp:
    csv_reader = csv.reader(fp, delimiter=",")
    for row in csv_reader:
      if len(row) and not row[0].startswith("#"):
        ip_string = socket.inet_ntoa(struct.pack('!L', int(row[0])))
        ip_to_country_dict[row[1]] = ip_string

  return ip_to_country_dict


def main():
  # Configure the random seed with a randomly chosen number for reproducibility
  random.seed(13)

  # Hardcorded domain an policy values
  foreign_domain = "foreign-demo-domain.us"
  foreign_policy = "reject"
  my_domain = "my-demo-domain.at"
  my_policy = "none"

  # We want reports for the year 2017
  start_day = datetime(2017, 1, 1)
  num_days = 365

  # Paths (names) to store report to
  base_path = "reports"
  incoming_path = os.path.join(base_path, "incoming")
  outgoing_path = os.path.join(base_path, "outgoing")

  # Create dirs if not there
  if not os.path.exists(incoming_path):
    os.makedirs(incoming_path)
  if not os.path.exists(outgoing_path):
    os.makedirs(outgoing_path)

  # Load IP data from csv
  ip_csv_path = "ipv4_to_country.csv"
  ip_data = get_country_to_ip_dict(ip_csv_path)

  # Available raw DKIM and SPF results to choose from randomly
  # A DKIM result of `None` means no raw DKIM result
  dkim_result_choices = [None, "none", "pass", "fail", "policy", "neutral",
      "temperror", "permerror"]
  spf_result_choices = ["none", "neutral", "pass", "fail", "softfail",
      "temperror", "permerror"]

  # Bounds for random message count
  message_count_min = 0
  message_count_max = 100

  # Iterate over two sets of basic report data one for incoming and one for
  # outgoing reports and ...
  for report_vars in [
      {"reporter": foreign_domain, "reportee": my_domain, "policy": my_policy,
      "base_path": incoming_path, "legitimate_country": "US"},
      {"reporter": my_domain, "reportee": foreign_domain,
      "policy": foreign_policy, "base_path": outgoing_path,
      "legitimate_country": "AT"}]:

    # ... create a report for each day using random values
    for day in get_report_days(start_day, num_days):
      report_vars["day"] = day

      report_vars["dkim_result"] = random.choice(dkim_result_choices)
      report_vars["spf_result"] = random.choice(spf_result_choices)
      report_vars["message_count"] = random.randint(message_count_min,
          message_count_max)

      # Assign IP address based on SPF result.
      if report_vars["spf_result"] == "pass":
        report_vars["source_ip"] = ip_data[report_vars["legitimate_country"]]

      else:
        report_vars["source_ip"] = random.choice(ip_data.values())

      # Genrate report data
      report_data = get_report_data(**report_vars)

      # Generate DMARC compliant report
      report_xml_string, report_name = generate_report(report_data)

      # Validate report schema
      validate_report(report_xml_string)

      report_path = os.path.join(report_vars["base_path"], report_name)
      with open(report_path, "w") as fp:
        fp.write(report_xml_string)



if __name__ == "__main__":
  main()