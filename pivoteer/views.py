import csv
import json
import datetime

from celery import group
from celery.result import GroupResult

from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from pivoteer.tasks import *
from pivoteer.forms import SubmissionForm
from pivoteer.models import HostRecord, WhoisRecord, MalwareRecord
from pivoteer.models import SearchEngineHits, TaskTracker


# Decides default time frame for new record searches
def cache_time():
    start_timestamp = datetime.datetime.utcnow()
    minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')
    current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
    desired_time = current_time - datetime.timedelta(hours=24)
    return desired_time


class PivotManager(View):

    def __init__(self):
        self.template_name = 'pivoteer.html'
        self.template_vars = {'SubmissionForm': SubmissionForm}

    @method_decorator(login_required(login_url='gateway_login'))
    def get(self, request):

        return render(request, self.template_name, self.template_vars)

    @method_decorator(login_required(login_url='gateway_login'))
    def post(self, request):

        task_tracking = {}
        submitted_form = SubmissionForm(request.POST)
        current_time = datetime.datetime.utcnow()
        desired_time = cache_time()

        if submitted_form.is_valid():
            indicator = submitted_form.cleaned_data['indicator']
            record_type = submitted_form.cleaned_data['record_type']
            indicator_type = submitted_form.indicator_type

            try:
                # Check if a recent task has been submitted for this indicator
                recent_tasks = TaskTracker.objects.get(keyword=indicator,
                                                       type=record_type,
                                                       date__gte=desired_time)

            except MultipleObjectsReturned:
                recent_tasks = TaskTracker.objects.filter(keyword=indicator,
                                                          type=record_type,
                                                          date__gte=desired_time).latest('date')

            except ObjectDoesNotExist:
                recent_tasks = None

            # If a recent task exists, use that one instead
            if recent_tasks:
                task_tracking['id'] = recent_tasks.group_id

            else:
                # Route to appropriate celery tasks according to record & indicator type
                if record_type == "current":

                    if indicator_type == 'domain':
                        new_task = group([domain_whois.s(indicator),
                                         domain_hosts.s(indicator)])()

                    elif indicator_type == 'ip':
                        new_task = group([ip_whois.s(indicator),
                                         ip_hosts.s(indicator)])()

                    else:
                        new_task = None

                elif record_type == "passive":
                    new_task = group([virustotal_passive.s(indicator, indicator_type),
                                      passivetotal_resolutions.s(indicator, indicator_type),
                                      internet_identity.s(indicator)])()

                elif record_type == "malware":
                    new_task = group([threatexpert_malware.s(indicator),
                                      virustotal_malware.s(indicator)])()

                elif record_type == "other":
                    new_task = group([google_search.s(indicator)])()

                else:
                    new_task = None

                # Track tasks according to searched indicator to reduce overhead
                if new_task:
                    # Enforce saving of group meta for tracking
                    new_task.save()

                    task_tracking['id'] = new_task.id
                    TaskTracker(group_id=new_task.id, keyword=indicator,
                                type=record_type, date=current_time).save()

                else:
                    task_tracking["errors"] = "Unexpected Failure"

        else:  # pass form errors back to user from async request
            task_tracking["errors"] = submitted_form.errors

        json_response = json.dumps(task_tracking)
        return HttpResponse(json_response, content_type="application/json")


# Check if task completed
# https://zapier.com/blog/async-celery-example-why-and-how/
class CheckTask(View):

    def __init__(self):
        self.template_name = "UnknownRecords.html"
        self.template_vars = {}

    @method_decorator(login_required(login_url='gateway_login'))
    def post(self, request):

        task = request.POST['task_id']
        res = GroupResult.restore(task)

        if res and not res.ready():
            return HttpResponse(json.dumps({"status": "loading"}), content_type="application/json")

        # Task completion allows for origin information to be pulled
        manager = RecordQueryManager()

        try:
            task_origin = TaskTracker.objects.get(group_id=task)
            record_type = task_origin.type
            indicator = task_origin.keyword

        except MultipleObjectsReturned:
            task_origin = TaskTracker.objects.filter(group_id=task).latest('date')
            record_type = task_origin.type
            indicator = task_origin.keyword

        except ObjectDoesNotExist:
            record_type = None

        # Pull data according to the record type
        if record_type == "current":
            # Collect whois record for current records
            whois_record = manager.collect_whois(indicator)
            self.template_vars["whois_record"] = whois_record.record

            # Collect host records for current records
            host_record = manager.collect_current_hosts(indicator)
            self.template_vars["host_record"] = host_record
            self.template_name = "CurrentRecords.html"

        elif record_type == "passive":
            host_records = manager.collect_passive(indicator)
            self.template_vars["passive_records"] = host_records
            self.template_name = "PassiveRecords.html"

        elif record_type == "malware":
            malware_records = manager.collect_malware(indicator)
            self.template_vars["malware_records"] = malware_records
            self.template_name = "MalwareRecords.html"

        elif record_type == "other":
            google_search = manager.collect_google(indicator)
            self.template_vars["google_search"] = google_search
            self.template_name = "OtherRecords.html"

        return render(request, self.template_name, self.template_vars)


class ExportRecords(View):

    def __init__(self):
        self.manager = RecordQueryManager()

        # Create the HttpResponse object with the appropriate CSV header.
        self.response = HttpResponse(content_type='text/csv')
        self.response['Content-Disposition'] = 'attachment; filename="exported_records.csv"'
        self.writer = csv.writer(self.response)

    @method_decorator(login_required(login_url='gateway_login'))
    def post(self, request):
        indicator = request.POST['indicator']
        export = request.POST['export']

        if indicator and export == 'all':
            self.export_current(indicator)
            self.export_passive(indicator)
            self.export_malware(indicator)
            self.export_other(indicator)

        elif indicator and export == 'current':
            self.export_current(indicator)
        elif indicator and export == 'passive':
            self.export_passive(indicator)
        elif indicator and export == 'malware':
            self.export_malware(indicator)
        elif indicator and export == 'other':
            self.export_other(indicator)

        return self.response

    def export_current(self, indicator):

        hosts = self.manager.collect_current_hosts(indicator)
        self.writer.writerow(['Resolution Date', 'Domain', 'IP Address', 'Source'])

        for host in hosts:
            record = [host.resolution_date, host.domain_name, host.ip_address, host.resolution_source]
            self.writer.writerow(record)

        self.line_separator()

        whois = self.manager.collect_whois(indicator)
        self.writer.writerow(['Whois Record'])
        self.writer.writerow([whois.record])
        self.line_separator()

    def export_passive(self, indicator):

        passive = self.manager.collect_passive(indicator)
        self.writer.writerow(['Resolution Date', 'Domain', 'IP Address', 'Source'])

        for record in passive:
            entry = [record.resolution_date, record.domain_name, record.ip_address, record.resolution_source]
            self.writer.writerow(entry)

        self.line_separator()

    def export_malware(self, indicator):

        malware = self.manager.collect_malware(indicator)
        self.writer.writerow(['Submission Date', 'SHA256', 'MD5', 'Source', 'Report Link'])

        for record in malware:
            entry = [record.submission_date, record.SHA256_value, record.MD5_value,
                     record.report_source, record.report_link]
            self.writer.writerow(entry)

        self.line_separator()

    def export_other(self, indicator):

        google = self.manager.collect_google(indicator)
        self.writer.writerow([google.result_count])
        self.writer.writerow(['Title', 'Description', 'Link'])

        for entry in google.results:
            self.writer.writerow(entry)
        self.line_separator()

    def line_separator(self):
        self.writer.writerow([])


# Centralized management on record queries
class RecordQueryManager(object):

    def __init__(self):
        self.desired_time = cache_time()

    def collect_current_hosts(self, indicator):

        host_record = HostRecord.objects.filter(Q(domain_name=indicator) | Q(ip_address=indicator),
                                                Q(resolution_date__gte=self.desired_time),
                                                Q(query_keyword=indicator))

        # Iterate for unique values - not ideal solution but will work for now
        resolutions = [indicator]
        cleaned_records = []

        for record in host_record:
            if record.domain_name not in resolutions:
                resolutions.append(record.domain_name)
                cleaned_records.append(record)

            elif record.ip_address not in resolutions:
                resolutions.append(record.ip_address)
                cleaned_records.append(record)

        return cleaned_records

    def collect_whois(self, indicator):

        try:
            record = WhoisRecord.objects.only('record').get(query_keyword=indicator,
                                                            query_date__gte=self.desired_time)
        except MultipleObjectsReturned:
            record = WhoisRecord.objects.only('record').filter(query_keyword=indicator,
                                                               query_date__gte=self.desired_time).latest('query_date')
        except ObjectDoesNotExist:
            record = None

        return record

    def collect_passive(self, indicator):

        host_records = HostRecord.objects.filter(~Q(resolution_source="DNS Query"),
                                                 ~Q(resolution_source="Robtex"),
                                                 Q(query_keyword=indicator))
        return host_records

    def collect_malware(self, indicator):

        malware_records = MalwareRecord.objects.filter(query_keyword=indicator)
        return malware_records

    def collect_google(self, indicator):

        try:
            search = SearchEngineHits.objects.get(query_keyword=indicator,
                                                  query_date__gte=self.desired_time)
        except MultipleObjectsReturned:
            search = SearchEngineHits.objects.filter(query_keyword=indicator,
                                                     query_date__gte=self.desired_time).latest('query_date')
        except ObjectDoesNotExist:
            search = None

        return search