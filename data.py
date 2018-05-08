"""
<Name>
  data.py

<Author>
  Lukas Puehringer <luk.puehringer@gmail.com>

<Started>
  May, 2018

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Python dictionary containing sample DMARC aggregate report data.

"""

sample_report = {
    # Report generator metadata
    "report_metadata": {
      "org_name": "reporter.org",
      "org_email": "postmaster@example.org",
      "extra_contact_info": "www.reporter.org",
      # "<report receiver domain>:<non-leap seconds since epoch>"
      "report_id": "reportee.org:1514847601",
      # The time range in UTC covered by messages in this report,
      # specified in seconds since epoch
      "date_range": {
        "begin": 1514761200,
        "end": 1514847600
      },
      # Optional list of error strings
      "errors": [],
    },
    "policy_published": {
      # The domain at which the DMARC record was found, i.e. report receiver
      "domain": "reportee.org",
      # Optional alignment modes for DKIM and SPF,
      # relaxed ("r") or strict ("s")
      "adkim": "r",
      "aspf": "r",
      # Policy actions applied to messages in this report,
      # "none", "quarantine" or "reject"
      # Policy applied to messages from report receiver domain
      "p": "none",
      # Policy applied to messages from report receiver subdomains
      "sp": "none",
      # The percent of messages to which policy applies
      "pct": 100
    },
    # List of all the authentication results that were evaluated by the
    # mail receiving system, i.e. report sender, for the given set of messages
    "records" : [
      {
        # NOTE: There is only one row per record (no idea why they call it row)
        "row": {
          # The connecting IP (v4 or v6)
          "source_ip": "8.8.8.8",
          # The number of matching messages
          "count": 42,
          # Taking into account everything else in the record,
          # the results of applying DMARC
          "policy_evaluated": {
            # The DMARC disposition applying to matching messages, i.e. the
            # policy specified p and sp, applied according to the DMARC
            # verification result, i.e. one of "none", "quarantine", "reject"
            "disposition": "none",
            # The DMARC-aligned DKIM and SPF authentication results,
            # "pass", "fail"
            "dkim": "pass",
            "spf": "fail",
            # Optional list of reasons that may affect DMARC disposition
            # or execution thereof
            "reasons": [
              {
                # One of "forwarded", "sampled_out", "trusted_forwarder",
                # "mailing_list", "local_policy", "other"
                "type": "other",
                # Optional comment
                "comment": "No reason"
              }
            ]
          }
        },
        "identifiers": {
          # Optional envelope recipient domain
          "envelope_to": "reporter.org",
          # The RFC5322.From domain
          "header_from": "reportee.org"
        },
        "auth_results": {
          # Optional list of DKIM authentication results
          # NOTE: One per DKIM signature in the matching emails
          "dkim": [
            {
              # The "d=" parameter in the DKIM signature
              "domain": "reportee.org",
              # Optionally the "s=" parameter in the DKIM signature
              "selector": "abc",
              # The DKIM verification result, one of "none", "pass", "fail",
              # "policy", "neutral", "temperror", "permerror"
              "result": "pass",
              # Optional extra information (e.g., from Authentication-Results)
              "human_result": "pass"
            }
          ],
          # List of SPF verification results (at least one)
          "spf": [
            {
              # The checked domain
              "domain": "reprotee.org",
              # The scope of the checked domain, "helo" or "mfrom"
              "scope": "helo",
              # SPF result, one of none, neutral, pass, fail, softfail,
              # temperror, permerror
              "result": "neutral"
            }
          ]
        }
      }
    ]
  }