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