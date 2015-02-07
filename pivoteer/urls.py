from django.conf.urls import patterns, url
from pivoteer import views

urlpatterns = patterns('',
    url(r'^$', views.PivotManager.as_view(), name='app_Pivoteer'),
    url(r'^tasks', views.CheckTask.as_view(), name='Pivoteer_Tasks'),
    url(r'^exports', views.ExportRecords.as_view(), name='Pivoteer_Export'),
)