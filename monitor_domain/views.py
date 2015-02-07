import datetime
import csv
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from monitor_domain.models import DomainMonitor, DomainAlert
from monitor_domain.forms import SubmissionForm, BulkSubmissionForm
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
User = get_user_model()


@login_required(login_url='gateway_login')
def domain_manager(request):

    # Get current timestamp for time range queries
    start_timestamp = datetime.datetime.utcnow()
    minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')
    current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')

    template_name = 'monitor_domain.html'
    template_vars = {'SubmissionForm': SubmissionForm, 'BulkSubmissionForm': BulkSubmissionForm}

    domain_list = User.objects.get(email__exact=request.user).domain_list

    if domain_list:
        monitoring = DomainMonitor.objects.filter(domain_name__in=domain_list)

        # Gather alerts that relate to compiled list of monitored IP addresses
        alert_list = DomainAlert.objects.filter(alert_time__gte=current_time - datetime.timedelta(hours=72),
                                                domain_name__in=domain_list)

        template_vars['monitor_list'] = monitoring
        template_vars['alert_list'] = alert_list

    return render(request, template_name, template_vars)


@login_required(login_url='gateway_login')
def add_monitor(request):

    lookup_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    success_message = 'Domain added for monitoring'
    failure_message = 'Unable to add domain for monitoring'

    if request.method == 'POST':

        submitted_form = SubmissionForm(request.POST)

        if submitted_form.is_valid():
            domain = submitted_form.cleaned_data['domain']
            current_user = User.objects.get(email__exact=request.user)

            try:
                DomainMonitor.objects.get(domain_name__exact=domain)

            except ObjectDoesNotExist:
                new_monitor = DomainMonitor(domain_name=domain,
                                            lookup_interval='24',
                                            next_lookup=lookup_time)

                try:
                    new_monitor.save()

                except:
                    messages.add_message(request, messages.WARNING, failure_message)

                else:
                    current_user.domain_list.append(domain)
                    current_user.save()
                    messages.add_message(request, messages.SUCCESS, success_message)

            else:
                if domain in current_user.domain_list:
                    messages.add_message(request, messages.WARNING, failure_message + ': already monitored')

                else:
                    current_user.domain_list.append(domain)
                    current_user.save()
                    messages.add_message(request, messages.SUCCESS, success_message)

        else:
            messages.add_message(request, messages.WARNING, failure_message + ': invalid domain')

    return redirect('app_MonitorDomain')


@login_required(login_url='gateway_login')
def bulk_monitor(request):

    lookup_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    success_message = 'Domains added for monitoring'

    if request.method == 'POST':

        submitted_form = BulkSubmissionForm(request.POST)

        if submitted_form.is_valid():
            current_user = User.objects.get(email__exact=request.user)
            domains = submitted_form.cleaned_data['domains']

            # Will definitely require optimization -
            # http://www.slideshare.net/Counsyl/efficient-djangoquery-setuse
            for domain in domains:

                try:
                    DomainMonitor.objects.get(domain_name__exact=domain)

                except ObjectDoesNotExist:
                    new_monitor = DomainMonitor(domain_name=domain,
                                                lookup_interval='24',
                                                next_lookup=lookup_time)
                    new_monitor.save()
                    current_user.domain_list.append(domain)
                    current_user.save()

                else:

                    if domain not in current_user.domain_list:
                        current_user.domain_list.append(domain)
                        current_user.save()

            messages.add_message(request, messages.WARNING, success_message)

    return redirect('app_MonitorDomain')


@login_required(login_url='gateway_login')
def del_monitor(request):

    current_user = User.objects.get(email__exact=request.user)
    success_message = 'Selected domains removed from monitoring'

    if request.method == 'POST':

        for domain in request.POST.getlist('choices'):

            try:
                DomainMonitor.objects.get(domain_name__exact=domain)

            except ObjectDoesNotExist:
                pass

            else:
                if domain in current_user.domain_list:
                    current_user.domain_list.remove(domain)

        current_user.save()
        messages.add_message(request, messages.SUCCESS, success_message)

    return redirect('app_MonitorDomain')


@login_required(login_url='gateway_login')
def export_monitor(request):

    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="monitored_domains.csv"'

    # Compile list of domains monitored by requesting user
    domain_list = User.objects.get(email__exact=request.user).domain_list
    monitoring = DomainMonitor.objects.filter(domain_name__in=domain_list)

    # Begin Writing to CSV object - Set Column Headings
    writer = csv.writer(response)
    writer.writerow(['Domain Name', 'Last Lookup', 'Last Hosts'])

    for monitor in monitoring:
        record = [monitor.domain_name, monitor.last_lookup, monitor.last_hosts]
        writer.writerow(record)

    return response