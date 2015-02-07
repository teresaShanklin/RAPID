from django.conf.urls import patterns, url
from monitor_domain.views import *

urlpatterns = patterns('',
    url(r'^$', domain_manager, name='app_MonitorDomain'),
    url(r'^add_monitor', add_monitor, name='MonitorDomain_add'),
    url(r'^del_monitor', del_monitor, name='MonitorDomain_del'),
    url(r'^bulk_monitor', bulk_monitor, name='MonitorDomain_bulk'),
    url(r'^export_monitor', export_monitor, name='MonitorDomain_export'),
)