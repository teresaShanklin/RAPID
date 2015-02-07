from django.conf.urls import patterns, include, url
from django.contrib import admin

from gateway import urls as gateway
from pivoteer import urls as pivoteer
from monitor_domain import urls as monitor_domain
from monitor_ip import urls as monitor_ip


urlpatterns = patterns('',
    url(r'^$', include(gateway)),
    url(r'^gateway/', include(gateway)),
    url(r'^pivoteer/', include(pivoteer)),
    url(r'^monitor_domain/', include(monitor_domain)),
    url(r'^monitor_ip/', include(monitor_ip)),
    url(r'^admin/', include(admin.site.urls))
)