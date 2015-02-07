from RAPID.checks import IndicatorCheck
from django import forms
import re


class SubmissionForm(forms.Form):
    ip = forms.CharField(label='IP Submission', widget=forms.TextInput())

    def clean_ip(self):
        submission = self.cleaned_data.get('ip').strip()

        verify = IndicatorCheck(submission)

        if not verify.valid_ip():
            raise forms.ValidationError('Invalid ip address')

        return submission


class BulkSubmissionForm(forms.Form):
    ips = forms.CharField(label='Bulk IP Address Submission', widget=forms.Textarea())

    def clean_ips(self):

        submission = self.cleaned_data.get('ips')
        raw_ips = re.split(r'[,;|\n ]+', submission)
        verified_ips = []

        for ip in raw_ips:

            verify = IndicatorCheck(submission)

            if verify.valid_ip():
                verified_ips.append(ip)

        return verified_ips