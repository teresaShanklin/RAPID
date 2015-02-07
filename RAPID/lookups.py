import os
import logging
import tldextract
import pythonwhois
import dns.resolver
import geoip2.database
from ipwhois import IPWhois
from ipwhois.ipwhois import IPDefinedError

logger = logging.getLogger(__name__)
current_directory = os.path.dirname(__file__)


def geolocate_ip(ip):

    geolocation_database = os.path.join(current_directory, 'GeoLite2-City.mmdb')
    reader = geoip2.database.Reader(geolocation_database)

    try:
        response = reader.city(ip)

        # Result list - city, state, country
        results = [response.city.name, response.subdivisions.most_specific.name, response.country.name]

        # Clean results of None entries and return to requester
        return [entry for entry in results if entry is not None]

    except ValueError:
        logger.debug("Invalid IP address passed")
        return None

    except geoip2.errors.AddressNotFoundError:
        logger.debug("IP address not found in database")
        return None

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)
        return None


def resolve_domain(domain):

    # Set resolver to Google openDNS servers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    try:
        query_answer = resolver.query(qname=domain)
        answer = [raw_data.address for raw_data in query_answer]
        return answer

    except dns.resolver.NXDOMAIN:
        logger.debug("NX Domain")
        return None

    except dns.resolver.Timeout:
        logger.debug("Query Timeout")
        return None

    except dns.resolver.NoAnswer:
        logger.debug("No Answer")
        return None

    except dns.resolver.NoNameservers:
        logger.debug("No Name Server")
        return None

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)
        return None


def lookup_domain_whois(domain):

    # Extract base domain name for lookup
    ext = tldextract.extract(domain)
    delimiter = "."
    sequence = (ext.domain, ext.tld)
    domain_name = delimiter.join(sequence)

    try:
        # Retrieve parsed record, then remove raw entry
        record = pythonwhois.get_whois(domain_name)
        record.pop("raw", None)
        return record

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)
        return None


def lookup_ip_whois(ip):

    try:
        # Retrieve parsed record, then remove raw entry
        record = IPWhois(ip).lookup()
        record.pop("raw", None)
        record.pop("raw_referral", None)
        return record

    except ValueError:
        logger.debug("Invalid IP address passed")
        return None

    except IPDefinedError:
        logger.debug("Private-use network IP address passed")
        return None

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)
        return None