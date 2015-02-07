from django.conf.urls import patterns, url
from gateway.views import main_page, logout_view, LoginPrompt, RegistrationPrompt, AccountManager


urlpatterns = patterns('',
    url(r'^$', main_page, name='gateway_main'),
    url(r'^logout/', logout_view, name='gateway_logout'),
    url(r'^login/', LoginPrompt.as_view(), name='gateway_login'),
    url(r'^register/', RegistrationPrompt.as_view(), name='gateway_register'),
    url(r'^manage/', AccountManager.as_view(), name='gateway_account'),
)