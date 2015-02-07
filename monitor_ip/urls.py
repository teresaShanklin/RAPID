from django.conf.urls import patterns, url
from monitor_ip.views import *


urlpatterns = patterns('',
    url(r'^$', ip_manager, name='app_MonitorIp'),
    url(r'^add_monitor', add_monitor, name='MonitorIp_add'),
    url(r'^del_monitor', del_monitor, name='MonitorIp_del'),
    url(r'^bulk_monitor', bulk_monitor, name='MonitorIp_bulk'),
    url(r'^export_monitor', export_monitor, name='MonitorIp_export'),
)