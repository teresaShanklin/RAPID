import re
import json
import dateutil.parser
from django.core.exceptions import ObjectDoesNotExist
from robobrowser import RoboBrowser
import html5lib
import requests
from pivoteer.models import ExternalSessions
from RAPID.configurations import InternetIdentityCredentials
from RAPID.checks import IndicatorCheck


class MechanizedScraper(object):

    def __init__(self):

        # Create and configure browser object for navigation
        agent = 'Mozilla/5.0 (Windows NT 5.1; rv:23.0) Gecko/20100101 Firefox/23.0'
        self.browser = RoboBrowser(user_agent=agent, parser='html5lib')

    def extract_string(self, full_string, first_param, last_param):

        try:
            start = full_string.index(first_param) + len(first_param)
            end = full_string.index(last_param, start)
            return full_string[start:end]

        except ValueError:
            return ""

    def check_type(self, indicator):
        verify = IndicatorCheck(indicator)
        return verify.discover_type()


class RobtexScraper(MechanizedScraper):

    def __init__(self):
        MechanizedScraper.__init__(self)

    def run(self, ip):

        results = []

        url_param = ip.replace(".", "/")
        url = "https://www.robtex.com/en/advisory/ip/" + url_param + "/shared.html"

        self.browser.open(url)

        parser = self.browser.parsed
        search = parser.find("span", {"id": "shared_ma"})

        if search is not None:
            # count = self.extract_string(search.text, "(", " shown")
            # if int(count) <= 50:

            for result in search.parent.parent.find("ol", {"class": "xbul"}).findChildren('li'):
                result_value = result.text

                if ' ' in result_value:
                    result_value = re.sub(' ', '.', result_value)
                    results.append(result_value)

                else:
                    results.append(result_value)

            # else:
            #    results.append("%s domains identified" % str(count))

        return results


class GoogleScraper(MechanizedScraper):

    def __init__(self):
        MechanizedScraper.__init__(self)
        self.results = {'top_results': [], 'result_count': 0}

    def run(self, query):

        self.browser.open("https://www.google.com")

        form = self.browser.get_form(id="gbqf")
        form['q'].value = "\"" + query + "\""
        self.browser.submit_form(form)

        parser = self.browser.parsed

        # Prepare tables
        headlines = []
        links = []
        descriptions = []

        # Return number of results from search
        count = parser.find('div', {'id': 'resultStats'})
        sanitized_count = str(count)

        first = "<div id=\"resultStats\">"
        last = "<nobr>"

        self.results['result_count'] = self.extract_string(sanitized_count, first, last)

        # Return first page of results #
        for div in parser.find_all('div', {'class': 'rc'}):

            try:
                headline = div.h3.a.text
                link = div.h3.a['href']
                description = div.find('span', {'class': 'st'}).text
                result = [headline, link, description]
                self.results['top_results'].append(result)

            except:
                pass

        return self.results


class VirusTotalScraper(MechanizedScraper):

    def __init__(self):
        MechanizedScraper.__init__(self)

        # Set additional header parameters; VirusTotal won't return content without them
        self.browser.session.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        self.browser.session.headers["Accept-Encoding"] = "gzip, deflate"
        self.browser.session.headers["Accept-Language"] = "en-US,en;q=0.5"

    def run(self, indicator):

        indicator_type = self.check_type(indicator)

        if indicator_type == "ip":
            url = "https://www.virustotal.com/en/ip-address/" + indicator + "/information/"
            self.browser.open(url)

        elif indicator_type == "domain":
            url = "https://www.virustotal.com/en/domain/" + indicator + "/information/"
            self.browser.open(url)

    def parse_passive(self):

        results = []
        parsed_html = self.browser.parsed

        try:
            alert = parsed_html.find('div', {'id': 'dns-resolutions'}).find('div', {'class': 'alert'})

        except AttributeError:
            alert = None

        if not alert:
            records = parsed_html.find('div', {'id': 'dns-resolutions'})

            if records is not None:
                for item in records.find_all('div'):
                    entry = item.text.replace(" ", "").splitlines()
                    entry = filter(None, entry)
                    results.append(list(entry))

        return results

    def parse_malware(self):

        results = []
        parsed_html = self.browser.parsed
        alert = parsed_html.find('div', {'id': 'dns-resolutions'}).find('div', {'class': 'alert'})

        if not alert:
            records = parsed_html.find('div', {'id': 'detected-communicating'})

            if records is not None:
                for item in records.find_all('div'):
                    raw = item.text.splitlines()
                    entries = [entry.strip() for entry in raw]
                    cleaned = filter(None, entries)
                    results.append(list(cleaned)[1:])  # Remove detection ratio

        return results


class ThreatExpertScraper(MechanizedScraper):

    def __init__(self):
        MechanizedScraper.__init__(self)

    def run(self, query):

        results = []
        self.browser.open("http://www.threatexpert.com/reports.aspx")

        form = self.browser.get_form(action="reports.aspx")
        form['find'].value = "\"" + query + "\""
        self.browser.submit_form(form)

        parser = self.browser.parsed

        # Return number of results from search [0] + number of pages of results [1]
        section = parser.find('span', {'id': 'txtResults'}).find_all('table')

        if section:

            if len(section) > 1:
                page_count = len(section[1].find_all('td')) - 1 # Acquire page count
            else:
                page_count = 1

            # scrape current page
            data = section[0].find_all('tr')
            page = self.scrape_page(data)
            results.extend(page)

            # Gather records from subsequent pages
            for x in range(2, page_count + 1):
                url = "http://www.threatexpert.com/reports.aspx?page=%s&find=%s" % (x, query)
                self.browser.open(url)
                parser = self.browser.parsed
                section = parser.find('span', {'id': 'txtResults'}).find('table')

                if section:
                    data = section.find_all('tr')
                    page = self.scrape_page(data)
                    results.extend(page)

        return results

    def scrape_page(self, data):

        results = []
        container = []

        for row in data[1:]:  # Remove Headers
            entries = row.find_all('td')

            for entry in entries:
                link = entry.find('a')

                if link:
                    container.append(link['href'][16:])  # splice off report.aspx?md5=
                else:
                    container.append(entry.text)

            raw_time = container[0]  # Default Date Format 6/8/2013 3:05:55 AM
            clean_time = dateutil.parser.parse(raw_time)  # Convert to datetime object
            container[0] = clean_time.strftime('%Y-%m-%d %H:%M:%S')

            # Container = [Date, Risk, Origin, MD5], Remove Risk and Origin
            results.append([container[0], container[-1]])
            container[:] = []

        return results


class InternetIdentityScraper(MechanizedScraper):

    def __init__(self):
        MechanizedScraper.__init__(self)
        self.service = "InternetIdentity"
        self.credentials = InternetIdentityCredentials()
        self.results = []

    def run(self, indicator):

        self.load_cookie()
        cookie_valid = self.check_cookie()

        if cookie_valid:
            indicator_type = self.check_type(indicator)

            if indicator_type == "ip":
                self.scrape_data(indicator, "A")  # query_type = "A" for IP

            elif indicator_type == "domain":
                self.scrape_data(indicator, "H")  # query_type = "H" for domain
                self.scrape_data(indicator, "X")  # query_type = "X" for sub-domains

        return self.results

    def load_cookie(self):

        try:
            session = ExternalSessions.objects.get(service=self.service)
            cookie = requests.utils.cookiejar_from_dict(json.loads(session.cookie))

            self.browser.session.cookies = cookie
            valid_cookie = self.check_cookie()

            if not valid_cookie:
                self.login()

        except ObjectDoesNotExist:
            self.login()

    def check_cookie(self):

        url = "https://research.iad.internetidentity.com"
        self.browser.open(url)
        parser = self.browser.parsed

        # Verify login succeeded
        login_test = parser.find_all('a', {'href': '/logout.php'})

        if login_test:
            return True

        return False

    def save_cookie(self):

        cookie = json.dumps(requests.utils.dict_from_cookiejar(self.browser.session.cookies))

        try:
            session = ExternalSessions.objects.get(service=self.service)
            session.cookie = cookie
            session.save(update_fields=['cookie'])

        except ObjectDoesNotExist:
            session = ExternalSessions(service=self.service,
                                       cookie=cookie)
            session.save()

    def login(self):

        url = "https://research.iad.internetidentity.com/login.php"
        self.browser.open(url)

        form = self.browser.get_form()
        form['username'].value = self.credentials.username
        form['password'].value = self.credentials.password
        self.browser.submit_form(form)
        self.save_cookie()

    def scrape_data(self, indicator, query_type):

        passive_table = []
        search_period = '5'

        # 1 = Current day
        # 2 = Current month
        # 3 = Past 6 months
        # 4 = Past year
        # 5 = Full Historical

        format = '0'
        # 0 = Display results on screen
        # 1 = Output to CSV file (Comma separated w/o quotes)
        # 2 = Output to CSV file (Comma separated with quotes)
        # 3 = Output to CSV file (Tab separated w/o quotes)
        # 4 = Output to CSV file (Tab separated with quotes)
        # 5 = Output to CSV file (Pipe separated w/o quotes)
        # 6 = Output to CSV file (Pipe separated with quotes)

        # queryType
        # A = Query IP Address or CIDR,
        # H = Query Hostname
        # X = Query Domain Name for Hosts
        # D = Query Domain for Authoritative Nameservers
        # N = Query Nameserver for Authoritative Domains

        url = "https://research.iad.internetidentity.com/index.php?search_period=" + search_period + "&format=" + format + "&queryType=" + query_type + "&target=" + indicator + "&submit=Submit+Query"

        self.browser.open(url)
        parser = self.browser.parsed

        passive_row = []

        for tr in parser.find_all('tr')[7:]:

            tds = []
            for td in tr.find_all('td'):
                tds.append(td.text.strip())

            # check for querytype to correctly display output
            if query_type == 'A' or query_type == 'X':
                IID_ip = tds[0]
                IID_asn = tds[1]
                IID_bgp = tds[2]
                IID_seen = tds[3]
                IID_host = tds[4]

            else:
                IID_host = tds[0]
                IID_seen = tds[1]
                IID_ip = tds[2]
                IID_asn = tds[3]
                IID_bgp = tds[4]

            passive_row = [IID_seen, IID_ip, IID_host]
            passive_table.append(passive_row[:])
            passive_row[:] = []
            tds[:] = []

        self.results.extend(passive_table)