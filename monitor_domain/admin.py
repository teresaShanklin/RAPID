from django.contrib import admin
from monitor_domain.models import DomainMonitor, DomainAlert


class DomainMonitorAdmin(admin.ModelAdmin):
    exclude = ('lookup_interval',)
    list_display = ('domain_name',)


class DomainAlertAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'alert_time', 'alert_text')

admin.site.register(DomainMonitor, DomainMonitorAdmin)
admin.site.register(DomainAlert, DomainAlertAdmin)
