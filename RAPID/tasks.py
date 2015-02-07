import os
import gzip
import urllib.request
from celery import shared_task
from django.core.mail import EmailMessage
from celery.task import periodic_task
from celery.schedules import crontab


@shared_task(name='deliver_email')
def deliver_email(subject=None, body=None, recipients=None):

    if recipients:

        for recipient in recipients:
            email = EmailMessage(subject, body, to=[recipient])
            email.send()



@periodic_task(bind=True, run_every=crontab(0, 0, day_of_month='7'))
def update_geolocation(self):

    # Establish desired paths and directories
    current_directory = os.path.dirname(__file__)
    compressed_filepath = os.path.join(current_directory, 'GeoLite2-City.mmdb.gz')
    uncompressed_filepath = os.path.join(current_directory, 'GeoLite2-City.mmdb')

    # Pull down current database file
    url = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz"
    urllib.request.urlretrieve(url, compressed_filepath)

    # Read and unzip compressed file to current directory
    zipped = gzip.open(compressed_filepath, "rb")
    uncompressed = open(uncompressed_filepath, "wb")
    uncompressed.write(zipped.read())

    zipped.close()
    uncompressed.close()

    # Remove zipped file
    os.remove(compressed_filepath)