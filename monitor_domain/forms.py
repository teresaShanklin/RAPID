from RAPID.checks import IndicatorCheck
from django import forms
import re


class SubmissionForm(forms.Form):
    domain = forms.CharField(label='Domain Submission', widget=forms.TextInput())

    def clean_domain(self):
        submission = self.cleaned_data.get('domain').strip().lower()

        verify = IndicatorCheck(submission)

        if not verify.valid_domain():
            raise forms.ValidationError('Invalid domain name')

        return submission


class BulkSubmissionForm(forms.Form):
    domains = forms.CharField(label='Bulk Domain Submission', widget=forms.Textarea())

    def clean_domains(self):

        submission = self.cleaned_data.get('domains')
        raw_domains = re.split(r'[,;|\n ]+', submission)
        verified_domains = []

        for domain in raw_domains:

            verify = IndicatorCheck(submission)

            if verify.valid_domain():
                verified_domains.append(domain.lower())

        return verified_domains