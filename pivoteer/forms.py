from django import forms
from RAPID.checks import IndicatorCheck


class SubmissionForm(forms.Form):

    indicator = forms.CharField(label='Indicator Submission', widget=forms.TextInput())
    record_type = forms.CharField(widget=forms.TextInput())
    indicator_type = "unknown"

    def clean_indicator(self):
        indicator = self.cleaned_data.get('indicator').strip().lower()
        verify = IndicatorCheck(indicator)

        if verify.valid_email():
            self.indicator_type = "email"

        elif verify.valid_domain():
            self.indicator_type = "domain"

        elif verify.valid_ip():
            self.indicator_type = "ip"

        if self.indicator_type != "domain" and self.indicator_type != "ip":
            raise forms.ValidationError('That is not a valid ip or domain')

        return indicator