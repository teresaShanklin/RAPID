import collections
from django.db import models
from djorm_pgarray.fields import TextArrayField
from jsonfield import JSONField


class HostRecord(models.Model):
    domain_name = models.CharField(max_length=253)
    ip_address = models.CharField(max_length=45)
    ip_location = TextArrayField(default=[])
    resolution_date = models.DateTimeField()
    resolution_source = models.CharField(max_length=50)
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()


class MalwareRecord(models.Model):
    submission_date = models.DateTimeField()
    MD5_value = models.CharField(max_length=32)
    SHA1_value = models.CharField(max_length=40)
    SHA256_value = models.CharField(max_length=64)
    report_link = models.URLField()
    report_source = models.CharField(max_length=50)
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()


class WhoisRecord(models.Model):
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()
    record = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})


class SearchEngineHits(models.Model):
    query_keyword = models.CharField(max_length=253)
    query_date = models.DateTimeField()
    result_count = models.CharField(max_length=50)
    results = TextArrayField(default=[])


class TaskTracker(models.Model):
    keyword = models.CharField(max_length=253)
    group_id = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    date = models.DateTimeField()


class ExternalSessions(models.Model):
    service = models.CharField(max_length=50)
    cookie = JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict})