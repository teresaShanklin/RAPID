from django import forms
from gateway.checks import PasswordChecks, UserChecks, OtherChecks


class RegistrationForm(forms.Form):
    email = forms.EmailField(label='Email Address', widget=forms.TextInput())
    password = forms.CharField(label='Password', widget=forms.PasswordInput())
    verify_password = forms.CharField(label='Verify Password', widget=forms.PasswordInput())
    registration_code = forms.CharField(label='Registration Token', widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)

        for field in self.fields.values():
            field.error_messages = {'required': '{fieldname} is required'.format(fieldname=field.label)}

    def clean_verify_password(self):
        verify = PasswordChecks()
        password = self.cleaned_data.get('password')
        verify_password = self.cleaned_data.get('verify_password')

        if not verify.passwords_match(password, verify_password):
            raise forms.ValidationError('The two password fields do not match.')

        else:
            if not verify.password_format(password):
                raise forms.ValidationError(verify.requirements)

        return password

    def clean_email(self):
        verify = UserChecks()
        email = self.cleaned_data.get('email')

        if verify.email_exists(email):
            raise forms.ValidationError('The address %s is already in use' % email)
        else:
            return email

    def clean_registration_code(self):
        verify = OtherChecks()
        token = self.cleaned_data.get('registration_code')

        if verify.token_exists(token):
            return token
        else:
            raise forms.ValidationError('Invalid registration code')


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email', widget=forms.TextInput())
    password = forms.CharField(label='Password', widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

        for field in self.fields.values():
            field.error_messages = {'required': '{fieldname} is required'.format(fieldname=field.label)}


class AccountManagementForm(forms.Form):
    email = forms.EmailField(label='Email Address', widget=forms.TextInput(), required=True)

    def __init__(self, *args, **kwargs):
        super(AccountManagementForm, self).__init__(*args, **kwargs)

        for field in self.fields.values():
            field.error_messages = {'required': '{fieldname} is required'.format(fieldname=field.label)}

    def clean_email(self):
        verify = UserChecks()
        email = self.cleaned_data.get('email')

        if verify.email_exists(email):
            raise forms.ValidationError('The address %s is already in use' % email)
        else:
            return email


class ChangePasswordForm(forms.Form):
    password = forms.CharField(label='Password', widget=forms.PasswordInput())
    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput())
    verify_password = forms.CharField(label='Verify Password', widget=forms.PasswordInput())

    def __init__(self, *args, **kwargs):
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

        for field in self.fields.values():
            field.error_messages = {'required': '{fieldname} is required'.format(fieldname=field.label)}

    def clean_verify_password(self):
        verify = PasswordChecks()
        new_password = self.cleaned_data.get('new_password')
        verify_password = self.cleaned_data.get('verify_password')

        if not verify.passwords_match(new_password, verify_password):
            raise forms.ValidationError('The two password fields do not match.')

        else:
            if not verify.password_format(new_password):
                raise forms.ValidationError(verify.requirements)

        return new_password