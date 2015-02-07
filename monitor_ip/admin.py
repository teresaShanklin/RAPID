from django.contrib import admin
from monitor_ip.models import IpMonitor, IpAlert


class IpMonitorAdmin(admin.ModelAdmin):
    exclude = ('lookup_interval',)
    list_display = ('ip_address',)


class IpAlertAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'alert_time', 'alert_text')

admin.site.register(IpMonitor, IpMonitorAdmin)
admin.site.register(IpAlert, IpMonitorAdmin)
