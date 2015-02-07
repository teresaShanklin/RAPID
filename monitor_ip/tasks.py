import datetime
from pivoteer.collectors.scrape import RobtexScraper
from celery.task import periodic_task, PeriodicTask
from celery.schedules import crontab
from monitor_ip.models import IpMonitor, IpAlert
from pivoteer.models import HostRecord
from RAPID.tasks import deliver_email
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
User = get_user_model()


class IpMonitoring(PeriodicTask):
    run_every = crontab()

    def run(self, **kwargs):
        start_timestamp = datetime.datetime.utcnow()
        minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')

        self.current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
        self.desired_time = self.current_time + datetime.timedelta(minutes=1)

        # Check for any overdue lookups
        self.check_overdue()

        ip_lookups = IpMonitor.objects.filter(next_lookup__gte=self.current_time,
                                              next_lookup__lte=self.desired_time)

        scraper = RobtexScraper()

        for lookup in ip_lookups:
            last_hosts = lookup.last_hosts
            ip_resolutions = scraper.run(lookup.ip_address)

            if ip_resolutions:
                HostRecord.objects.bulk_create([
                    HostRecord(domain_name=host,
                               ip_address=lookup.ip_address,
                               resolution_date=self.current_time,
                               resolution_source="Robtex",
                               query_keyword=lookup.ip_address,
                               query_date=self.current_time) for host in ip_resolutions
                ])

            if ip_resolutions and last_hosts:
                # Check for new or missing hosts since last lookup
                missing_hosts = list(set(last_hosts).difference(ip_resolutions))
                new_hosts = list(set(ip_resolutions).difference(last_hosts))

                # Sanitize ip address for safe email content
                sanitized_ip = lookup.ip_address.replace('.', '[.]')

                # Compile list of email recipients for a given IP address indicator
                email_recipients = User.objects.filter(ip_list__contains=[lookup.ip_address],
                                                       alerts=True).values_list('email', flat=True)

                # Compose alert and email content for hosting changes
                if missing_hosts and new_hosts:
                    sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                    sanitized_new = [host.replace('.', '[.]') for host in new_hosts]

                    alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                    self.create_alert(lookup.ip_address, alert_text)

                    alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                    self.create_alert(lookup.ip_address, alert_text)

                    email_subject = 'Domain Changes for ' + sanitized_ip
                    email_body = """ IP lookup performed at %s indicates that the tracked
                                     IP address %s has dropped the following domains: %s
                                     and has added the following domains: %s
                                 """ % (str(self.current_time), sanitized_ip,
                                        sanitized_missing, sanitized_new)

                    deliver_email.delay(email_subject, email_body, email_recipients)

                elif missing_hosts:
                    sanitized_missing = [host.replace('.', '[.]') for host in missing_hosts]
                    alert_text = 'Removed hosts: %s' % ', '.join(missing_hosts)
                    self.create_alert(lookup.ip_address, alert_text)

                    email_subject = 'Domain Drops for ' + sanitized_ip
                    email_body = """ IP lookup performed at %s indicates that the tracked
                                     IP address %s has dropped the following domains: %s
                                 """ % (str(self.current_time), sanitized_ip, sanitized_missing)

                    deliver_email.delay(email_subject, email_body, email_recipients)

                elif new_hosts:
                    sanitized_new = [host.replace('.', '[.]') for host in new_hosts]
                    alert_text = 'New hosts: %s' % ', '.join(new_hosts)
                    self.create_alert(lookup.ip_address, alert_text)

                    email_subject = 'Domain Additions for ' + sanitized_ip
                    email_body = """ IP lookup performed at %s indicates that the tracked
                                     IP address %s has added the following domains: %s
                                 """ % (str(self.current_time), sanitized_ip, sanitized_new)

                    deliver_email.delay(email_subject, email_body, email_recipients)

            # Update entry information
            lookup.last_hosts = ip_resolutions
            lookup.last_lookup = self.current_time
            lookup.next_lookup = self.current_time + datetime.timedelta(hours=lookup.lookup_interval)
            lookup.save()

    def check_overdue(self):
        # Check if a lookup is overdue
        overdue_lookup = IpMonitor.objects.filter(next_lookup__lt=self.current_time)
        overdue_text = 'Overdue lookup rescheduled'

        for entry in overdue_lookup:
            self.create_alert(entry.ip_address, overdue_text)
            entry.next_lookup = self.current_time
            entry.save()

    def create_alert(self, ip_address, alert_text):
        new_alert = IpAlert(ip_address=ip_address,
                            alert_text=alert_text,
                            alert_time=self.current_time)
        new_alert.save()


@periodic_task(bind=True, name='cleanup_ip_monitor', run_every=crontab(minute=30, hour=0))
def cleanup_monitor(self):
    """ Check for and remove orphan ip addresses that are no longer monitored by users """

    monitor_list = IpMonitor.objects.values_list('ip_address', flat=True)

    for ip in monitor_list:

        try:
            User.objects.get(domain_list__contains=[ip])

        except ObjectDoesNotExist:
            IpMonitor.objects.get(domain_name__exact=ip).delete()