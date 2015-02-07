import datetime
from celery.schedules import crontab
from celery.task import periodic_task, PeriodicTask
from monitor_domain.models import DomainMonitor, DomainAlert
from pivoteer.models import HostRecord
from RAPID.lookups import resolve_domain
from RAPID.tasks import deliver_email
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
User = get_user_model()


class DomainMonitoring(PeriodicTask):
    run_every = crontab()

    def run(self, **kwargs):
        start_timestamp = datetime.datetime.utcnow()
        minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')

        self.current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
        self.desired_time = self.current_time + datetime.timedelta(minutes=1)

        # Check for any overdue lookups
        self.check_overdue()

        # Compile list of domains to resolve based on lookup time
        domain_lookups = DomainMonitor.objects.filter(next_lookup__gte=self.current_time,
                                                      next_lookup__lte=self.desired_time)

        for lookup in domain_lookups:
            last_hosts = lookup.last_hosts
            domain_resolutions = resolve_domain(lookup.domain_name)

            if domain_resolutions:
                HostRecord.objects.bulk_create([
                    HostRecord(domain_name=lookup.domain_name,
                               ip_address=host,
                               resolution_date=self.current_time,
                               resolution_source="DNS Query",
                               query_keyword=lookup.domain_name,
                               query_date=self.current_time) for host in domain_resolutions
                ])

            if domain_resolutions and last_hosts:
                # Check for new or missing hosts since last lookup
                missing_hosts = list(set(last_hosts).difference(domain_resolutions))
                new_hosts = list(set(domain_resolutions).difference(last_hosts))

                # Sanitize domain name for safe email content
                sanitized_domain = lookup.domain_name.replace('.', '[.]')

                # Compile list of recipients for a given domain
                email_recipients = User.objects.filter(domain_list__contains=[lookup.domain_name],
                                                       alerts=True).values_list('email', flat=True)

                # Compose alert and email content for hosting changes
                if missing_hosts and new_hosts:
                    sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                    sanitized_new = [host.replace('.', '[.]') for host in new_hosts]

                    alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                    self.create_alert(lookup.domain_name, alert_text)

                    alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                    self.create_alert(lookup.domain_name, alert_text)

                    email_subject = 'IP Address Changes for ' + sanitized_domain
                    email_body = """ DNS lookup performed at %s indicates that the tracked
                                     domain %s has dropped the following IP addresses: %s
                                     and has added the following IP addresses: %s
                                 """ % (str(self.current_time), sanitized_domain,
                                        sanitized_missing, sanitized_new)

                    deliver_email.delay(email_subject, email_body, email_recipients)

                elif missing_hosts:
                    sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                    alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                    self.create_alert(lookup.domain_name, alert_text)

                    email_subject = 'IP Address Drops for ' + sanitized_domain
                    email_body = """ DNS lookup performed at %s indicates that the tracked
                                     domain %s has dropped the following IP addresses: %s
                                 """ % (str(self.current_time), sanitized_domain, sanitized_missing)

                    deliver_email.delay(email_subject, email_body, email_recipients)

                elif new_hosts:
                    sanitized_new = [host.replace('.', '[.]') for host in new_hosts]
                    alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                    self.create_alert(lookup.domain_name, alert_text)

                    email_subject = 'IP Address Additions for ' + sanitized_domain
                    email_body = """ DNS lookup performed at %s indicates that the tracked
                                     domain %s has changed to the following IP addresses: %s
                                 """ % (str(self.current_time), sanitized_domain, sanitized_new)

                    deliver_email.delay(email_subject, email_body, email_recipients)

            # Update entry information
            lookup.last_hosts = domain_resolutions
            lookup.last_lookup = self.current_time
            lookup.next_lookup = self.current_time + datetime.timedelta(hours=lookup.lookup_interval)
            lookup.save()

    def check_overdue(self):
        # Check if a lookup is overdue
        overdue_lookup = DomainMonitor.objects.filter(next_lookup__lt=self.current_time)
        overdue_text = 'Overdue lookup rescheduled'

        for entry in overdue_lookup:
            self.create_alert(entry.domain_name, overdue_text)
            entry.next_lookup = self.current_time
            entry.save()

    def create_alert(self, domain_name, alert_text):

        new_alert = DomainAlert(domain_name=domain_name,
                                alert_text=alert_text,
                                alert_time=self.current_time)
        new_alert.save()


@periodic_task(bind=True, name='cleanup_domain_monitor', run_every=crontab(minute=0, hour=0))
def cleanup_monitor(self):
    """ Check for and remove orphan domains that are no longer monitored by users """

    monitor_list = DomainMonitor.objects.values_list('domain_name', flat=True)

    for domain in monitor_list:

        try:
            User.objects.get(domain_list__contains=[domain])

        except ObjectDoesNotExist:
            DomainMonitor.objects.get(domain_name__exact=domain).delete()