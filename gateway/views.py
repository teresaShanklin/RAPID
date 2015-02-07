from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.views.generic.base import View
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
User = get_user_model()

from gateway.forms import LoginForm, RegistrationForm
from gateway.forms import AccountManagementForm, ChangePasswordForm
from gateway.models import RegistrationToken


@login_required(login_url='gateway_login')
def main_page(request):
    return render(request, 'gateway_navigation.html')


@login_required(login_url='gateway_login')
def logout_view(request):
    logout(request)
    return redirect('gateway_main')


class LoginPrompt(View):

    def __init__(self):
        self.template_name = 'gateway_login.html'
        self.template_vars = {'LoginForm': LoginForm}

    def get(self, request):

        return render(request, self.template_name, self.template_vars)

    def post(self, request):
        submitted_form = LoginForm(request.POST)
        self.template_vars['LoginForm'] = submitted_form

        if submitted_form.is_valid():
            email = submitted_form.cleaned_data['email']
            password = submitted_form.cleaned_data['password']
            user = authenticate(email=email, password=password)

            if user:
                login(request, user)
                return redirect('gateway_main')
            else:
                messages.add_message(request, messages.WARNING, 'Unsuccessful Login')

        return render(request, self.template_name, self.template_vars)


class RegistrationPrompt(View):

    def __init__(self):
        self.template_name = 'gateway_register.html'
        self.template_vars = {'RegistrationForm': RegistrationForm}

    def get(self, request):
        return render(request, self.template_name, self.template_vars)

    def post(self, request):
        submitted_form = RegistrationForm(request.POST)
        self.template_vars['RegistrationForm'] = submitted_form

        if submitted_form.is_valid():
            email = submitted_form.cleaned_data['email']
            password = submitted_form.cleaned_data['password']
            token = submitted_form.cleaned_data['registration_code']

            User.objects.create_user(email=email, password=password, is_active=True)
            RegistrationToken.objects.get(token__exact=token).delete()

            messages.add_message(request, messages.SUCCESS, 'Account Successfully Created')
            return redirect('gateway_main')

        return render(request, self.template_name, self.template_vars)


class AccountManager(View):

    def __init__(self):
        self.template_name = 'gateway_account.html'
        self.template_vars = {'AccountManagementForm': AccountManagementForm,
                              'ChangePasswordForm': ChangePasswordForm}

    @method_decorator(login_required(login_url='gateway_login'))
    def get(self, request):
        return render(request, self.template_name, self.template_vars)

    @method_decorator(login_required(login_url='gateway_login'))
    def post(self, request):

        email_change = 'email' in request.POST
        password_change = 'password' in request.POST
        alert_toggle = 'email_toggle' in request.POST

        if email_change:
            change_state = self.change_details(request)
        elif password_change:
            change_state = self.change_password(request)
        elif alert_toggle:
            change_state = self.toggle_alerts(request)
        else:
            change_state = False

        if change_state:
            return redirect('gateway_account')

        return render(request, self.template_name, self.template_vars)

    def change_password(self, request):

        submitted_form = ChangePasswordForm(request.POST)
        self.template_vars['ChangePasswordForm'] = submitted_form

        if submitted_form.is_valid():
            password = submitted_form.cleaned_data['password']
            new_password = submitted_form.cleaned_data['new_password']
            user = authenticate(email=request.user, password=password)

            if user:
                user.set_password(new_password)
                messages.add_message(request, messages.SUCCESS, 'Password Changed')
                return True
            else:
                messages.add_message(request, messages.WARNING, 'Incorrect password')

        return False

    def change_details(self, request):

        current_user = User.objects.get(email__exact=request.user)
        submitted_form = AccountManagementForm(request.POST)
        self.template_vars['AccountManagementForm'] = submitted_form

        if submitted_form.is_valid():
            new_email = submitted_form.cleaned_data['email']
            current_user.email = new_email
            current_user.save()

            messages.add_message(request, messages.SUCCESS, 'User details updated')
            return True

        return False

    def toggle_alerts(self, request):

        try:
            current_user = User.objects.get(email__exact=request.user)
            alert_status = current_user.alerts

            if alert_status:
                current_user.alerts = False
            else:
                current_user.alerts = True

            current_user.save()
            return True

        except:
            return False