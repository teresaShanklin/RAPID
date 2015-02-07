from __future__ import absolute_import

import datetime

from RAPID.celery import app
from RAPID.configurations import ApiKeys
from RAPID.lookups import lookup_ip_whois, lookup_domain_whois, resolve_domain, geolocate_ip

from pivoteer.collectors.scrape import RobtexScraper, GoogleScraper, InternetIdentityScraper
from pivoteer.collectors.scrape import VirusTotalScraper, ThreatExpertScraper
from pivoteer.collectors.api import PassiveTotal

from pivoteer.models import HostRecord, MalwareRecord, WhoisRecord
from pivoteer.models import SearchEngineHits


@app.task(bind=True)
def domain_whois(self, domain):

    current_time = datetime.datetime.utcnow()
    record = lookup_domain_whois(domain)

    if record:
        record_entry = WhoisRecord(query_keyword=domain, query_date=current_time, record=record)
        record_entry.save()


@app.task(bind=True)
def ip_whois(self, ip_address):

    current_time = datetime.datetime.utcnow()
    record = lookup_ip_whois(ip_address)

    if record:
        record_entry = WhoisRecord(query_keyword=ip_address, query_date=current_time, record=record)
        record_entry.save()


@app.task(bind=True)
def domain_hosts(self, domain):

    current_time = datetime.datetime.utcnow()
    hosts = resolve_domain(domain)
    source = "DNS Query"

    if hosts:
        HostRecord.objects.bulk_create([
            HostRecord(domain_name=domain,
                       ip_address=host,
                       ip_location=geolocate_ip(host),
                       resolution_date=current_time,
                       resolution_source=source,
                       query_keyword=domain,
                       query_date=current_time) for host in hosts
        ])


@app.task(bind=True)
def ip_hosts(self, ip_address):

    current_time = datetime.datetime.utcnow()
    scraper = RobtexScraper()
    hosts = scraper.run(ip_address)
    ip_location = geolocate_ip(ip_address),
    source = "Robtex"

    if hosts:
        HostRecord.objects.bulk_create([
            HostRecord(domain_name=host,
                       ip_address=ip_address,
                       ip_location=ip_location,
                       resolution_date=current_time,
                       resolution_source=source,
                       query_keyword=ip_address,
                       query_date=current_time) for host in hosts
        ])


@app.task(bind=True)
def google_search(self, query):
    current_time = datetime.datetime.utcnow()
    scraper = GoogleScraper()
    results = scraper.run(query)

    if results:
        record_entry = SearchEngineHits(query_keyword=query,
                                        query_date=current_time,
                                        result_count=results['result_count'],
                                        results=results['top_results'])
        record_entry.save()


@app.task(bind=True)
def internet_identity(self, indicator):

    current_time = datetime.datetime.utcnow()
    source = "InternetIdentity"
    scraper = InternetIdentityScraper()
    passive = scraper.run(indicator)  # returns table of data rows [Date, IP, Domain]

    if passive:
        # Delete old entries before inserting new ones - not ideal solution but will work for now
        HostRecord.objects.filter(query_keyword=indicator, resolution_source=source).delete()

        HostRecord.objects.bulk_create([
            HostRecord(domain_name=record[2],
                       ip_address=record[1],
                       ip_location=geolocate_ip(record[1]),
                       resolution_date=record[0],
                       resolution_source=source,
                       query_keyword=indicator,
                       query_date=current_time) for record in passive
        ])


@app.task(bind=True)
def virustotal_passive(self, indicator, indicator_type):

    current_time = datetime.datetime.utcnow()
    scraper = VirusTotalScraper()
    scraper.run(indicator)
    passive = scraper.parse_passive()
    source = "VirusTotal"

    if passive:
        # Delete old entries before inserting new ones - not ideal solution but will work for now
        HostRecord.objects.filter(query_keyword=indicator, resolution_source=source).delete()

        if indicator_type == "ip":
            ip_location = geolocate_ip(indicator)

            HostRecord.objects.bulk_create([
                HostRecord(domain_name=record[1],
                           ip_address=indicator,
                           ip_location=ip_location,
                           resolution_date=record[0],
                           resolution_source=source,
                           query_keyword=indicator,
                           query_date=current_time) for record in passive
            ])

        elif indicator_type == "domain":
            HostRecord.objects.bulk_create([
                HostRecord(domain_name=indicator,
                           ip_address=record[1],
                           ip_location=geolocate_ip(record[1]),
                           resolution_date=record[0],
                           resolution_source=source,
                           query_keyword=indicator,
                           query_date=current_time) for record in passive
            ])


@app.task(bind=True)
def virustotal_malware(self, indicator):

    current_time = datetime.datetime.utcnow()
    base_url = "https://www.virustotal.com/en/file/"
    scraper = VirusTotalScraper()
    scraper.run(indicator)
    malware = scraper.parse_malware()
    source = "VirusTotal"

    if malware:
        # Delete old entries before inserting new ones - not ideal solution but will work for now
        MalwareRecord.objects.filter(query_keyword=indicator, report_source=source).delete()

        MalwareRecord.objects.bulk_create([
            MalwareRecord(submission_date=record[0],
                          SHA256_value=record[1],
                          report_link=base_url + str(record[1] + "/analysis"),
                          report_source=source,
                          query_keyword=indicator,
                          query_date=current_time) for record in malware
            ])


@app.task(bind=True)
def threatexpert_malware(self, query):

    current_time = datetime.datetime.utcnow()
    base_url = "http://threatexpert.com/report.aspx?md5="
    scraper = ThreatExpertScraper()
    malware = scraper.run(query)
    source = "ThreatExpert"

    if malware:
        # Delete old entries before inserting new ones - not ideal solution but will work for now
        MalwareRecord.objects.filter(query_keyword=query, report_source=source).delete()

        MalwareRecord.objects.bulk_create([
            MalwareRecord(submission_date=record[0],
                          MD5_value=record[1],
                          report_link=base_url + str(record[1]),
                          report_source=source,
                          query_keyword=query,
                          query_date=current_time) for record in malware
            ])


@app.task(bind=True)
def passivetotal_resolutions(self, indicator, indicator_type):

    current_time = datetime.datetime.utcnow()
    collector = PassiveTotal(ApiKeys.passive_total)
    response = collector.search(indicator)
    source = "PassiveTotal"

    try:  # Attempt to gather resolutions from query
        resolutions = response['results']['resolutions']
    except Exception as unexpected_error:
        print(unexpected_error)
        resolutions = None

    if resolutions:

        cleaned = []

        # Cleanup and de-duplicate resolution results
        for entry in resolutions:

            if entry['firstSeen'] != 'None':
                cleaned.append((entry['value'], entry['firstSeen'], entry['country']))

            if entry['lastSeen'] != 'None' and entry['lastSeen'] != entry['firstSeen']:
                cleaned.append((entry['value'], entry['lastSeen'], entry['country']))

        # Delete old entries before inserting new ones - not ideal solution but will work for now
        HostRecord.objects.filter(query_keyword=indicator, resolution_source=source).delete()

        if indicator_type == "ip":

            ip_location = geolocate_ip(indicator)

            HostRecord.objects.bulk_create([
                HostRecord(domain_name=entry[0],
                           ip_address=indicator,
                           ip_location=ip_location,
                           resolution_date=entry[1],
                           resolution_source=source,
                           query_keyword=indicator,
                           query_date=current_time) for entry in cleaned
            ])

        elif indicator_type == "domain":

            HostRecord.objects.bulk_create([
                HostRecord(domain_name=indicator,
                           ip_address=entry[0],
                           ip_location=[entry[2]],
                           resolution_date=entry[1],
                           resolution_source=source,
                           query_keyword=indicator,
                           query_date=current_time) for entry in cleaned
            ])