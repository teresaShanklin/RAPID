"""
Indicator Type Checking
"""
from IPy import IP
import tldextract
import re


class IndicatorCheck(object):

    def __init__(self, submission):

        self.indicator = submission

    def valid_ip(self):

        try:
            if str(IP(self.indicator)) == str(self.indicator):
                return True
            else:
                return False

        except ValueError:
            return False

    def valid_email(self):

        if re.match(r"[^@]+@[^@]+\.[^@]+", self.indicator):
            return True
        else:
            return False

    def valid_domain(self):

        ext = tldextract.extract(self.indicator)
        tld = ext.tld
        domain = ext.domain

        if tld and domain:
            return True
        else:
            return False

    def discover_type(self):

        if self.valid_ip():
            return "ip"

        elif self.valid_email():
            return "email"

        elif self.valid_domain():
            return "domain"

        else:
            return None