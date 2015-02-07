import csv
import datetime
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from monitor_ip.models import IpMonitor, IpAlert
from monitor_ip.forms import SubmissionForm, BulkSubmissionForm
from django.contrib.auth import get_user_model
User = get_user_model()


@login_required(login_url='gateway_login')
def ip_manager(request):

    # Get current timestamp for time range queries
    start_timestamp = datetime.datetime.utcnow()
    minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')
    current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')

    template_name = 'monitor_ip.html'
    template_vars = {'SubmissionForm': SubmissionForm, 'BulkSubmissionForm': BulkSubmissionForm}

    # Compile list of ip addresses monitored by requesting user - ip_address
    ip_list = User.objects.get(email__exact=request.user).ip_list

    if ip_list:
        monitoring = IpMonitor.objects.filter(ip_address__in=ip_list)

        # Gather alerts that relate to compiled list of monitored IP addresses
        alert_list = IpAlert.objects.filter(alert_time__gte=current_time - datetime.timedelta(hours=72),
                                            ip_address__in=ip_list)

        template_vars['monitor_list'] = monitoring
        template_vars['alert_list'] = alert_list

    return render(request, template_name, template_vars)


@login_required(login_url='gateway_login')
def add_monitor(request):

    current_user = str(request.user)
    lookup_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    success_message = 'IP address added for monitoring'
    failure_message = 'Unable to add IP address for monitoring'

    if request.method == 'POST':

        submitted_form = SubmissionForm(request.POST)

        if submitted_form.is_valid():
            ip = submitted_form.cleaned_data['ip']
            current_user = User.objects.get(email__exact=request.user)

            try:
                IpMonitor.objects.get(ip_address__exact=ip)

            except ObjectDoesNotExist:
                new_monitor = IpMonitor(ip_address=ip,
                                        lookup_interval='24',
                                        next_lookup=lookup_time)

                try:
                    new_monitor.save()

                except:
                    messages.add_message(request, messages.WARNING, failure_message)

                else:
                    current_user.ip_list.append(ip)
                    current_user.save()
                    messages.add_message(request, messages.SUCCESS, success_message)

            else:

                if ip in current_user.ip_list:
                    messages.add_message(request, messages.WARNING, failure_message + ': already monitored')

                else:
                    current_user.ip_list.append(ip)
                    current_user.save()
                    messages.add_message(request, messages.SUCCESS, success_message)

        else:
            messages.add_message(request, messages.WARNING, failure_message + ': invalid ip address')

    return redirect('app_MonitorIp')


@login_required(login_url='gateway_login')
def bulk_monitor(request):

    lookup_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    success_message = 'IP addresses added for monitoring'

    if request.method == 'POST':

        submitted_form = BulkSubmissionForm(request.POST)

        if submitted_form.is_valid():
            current_user = User.objects.get(email__exact=request.user)
            ips = submitted_form.cleaned_data['ips']

            # Will definitely require optimization -
            # http://www.slideshare.net/Counsyl/efficient-djangoquery-setuse
            for ip in ips:

                try:
                    IpMonitor.objects.get(ip_address__exact=ip)

                except ObjectDoesNotExist:
                    new_monitor = IpMonitor(ip_address=ip,
                                            lookup_interval='24',
                                            next_lookup=lookup_time)
                    new_monitor.save()
                    current_user.ip_list.append(ip)
                    current_user.save()

                else:

                    if ip not in current_user.ip_list:
                        current_user.ip_list.append(ip)
                        current_user.save()

            messages.add_message(request, messages.WARNING, success_message)

    return redirect('app_MonitorIp')


@login_required(login_url='gateway_login')
def del_monitor(request):

    current_user = User.objects.get(email__exact=request.user)
    success_message = 'Selected IP addresses removed from monitoring'

    if request.method == 'POST':

        for ip in request.POST.getlist('choices'):

            try:
                IpMonitor.objects.get(ip_address__exact=ip)

            except ObjectDoesNotExist:
                pass

            else:
                if ip in current_user.ip_list:
                    current_user.ip_list.remove(ip)

        current_user.save()

        messages.add_message(request, messages.SUCCESS, success_message)

    return redirect('app_MonitorIp')


@login_required(login_url='gateway_login')
def export_monitor(request):

    # Create the HttpResponse object with the appropriate CSV header.
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="monitored_ips.csv"'

    # Compile list of domains monitored by requesting user
    ip_list = User.objects.get(email__exact=request.user).ip_list
    monitoring = IpMonitor.objects.filter(ip_address__in=ip_list)

    # Begin Writing to CSV object - Set Column Headings
    writer = csv.writer(response)
    writer.writerow(['IP Address', 'Last Lookup', 'Last Hosts'])

    for monitor in monitoring:
        record = [monitor.ip_address, monitor.last_lookup, monitor.last_hosts]
        writer.writerow(record)

    return response