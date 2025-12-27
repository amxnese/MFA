from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .utils import send_otp, password_validation, generate_otp
from django.contrib.auth import authenticate, login as auth_login
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import string
import time
import re

# storing otp's
otp_store = {}
OTP_VALIDITY = 300 # 5 seconds

def signup(request):
    if request.method == 'POST':
        username = request.POST['username'].strip()
        email = request.POST['email'].strip()
        password = request.POST['password']

        # Email Validation
        try:
            validate_email(email)
        except ValidationError:
            return render(request, 'accounts/signup.html', {
                'email': email,
                'error': 'Invalid email format.',
                'next_action': 'signup'
            })
        
        # Password Validation
        if not password_validation(password):
            return render(request, 'accounts/signup.html', {
                'email': email,
                'error': 'invalid password',
                'next_action': 'signup'
            })
        
        # Username Validation
        if User.objects.filter(username=username).exists():
                    return render(request, 'accounts/signup.html', {
                        'email': email,
                        'error': 'Username already exists. Choose another one.',
                        'next_action': 'signup'
                    })

        # gererating the otp and rendering to the verify otp page
        otp = generate_otp()
        otp_store[email] = {'otp': otp,'created_at': time.time(), 'data': {'username': username, 'password': password}}
        send_otp(email, otp)
        return render(request, 'accounts/verify_otp.html', {
            'email': email,
            'next_action': 'signup'}
        )
    return render(request, 'accounts/signup.html')

def verify_otp(request):
    if request.method == 'POST':
        # gathering information
        email = request.POST['email']
        otp = request.POST['otp']
        otp_created_at = otp_store[email]['created_at']
        action = request.POST['next_action']

        # checking if the otp is still available
        if time.time() - otp_created_at > OTP_VALIDITY:
            del otp_store[email]
            return render(request, 'accounts/verify_otp.html', {'email': email, 'error': 'OTP Expired', 'next_action': action})

        # Case where The otp is valid
        if email in otp_store and otp_store[email]['otp'] == otp:
            # verifying for a sign up action
            if action == 'signup':
                # Gathering username and password
                data = otp_store[email]['data']
                user = User.objects.create_user(username=data['username'], email=email, password=data['password'])
                # deleting the consumed otp
                del otp_store[email]

                auth_login(request, user)
                return redirect('welcome', username=user.username)
            # logging in case 
            elif action == 'login':
                username = otp_store[email]['data']['username']
                user = User.objects.get(username=username)
                del otp_store[email]
                auth_login(request, user)
                return redirect('welcome', username=user.username)

            # forgot password case
            elif action == 'forgot_password':
                return redirect('reset_password', email=email)
        else:
            return render(request, 'accounts/verify_otp.html', {'email': email, 'error': 'Invalid OTP', 'next_action': action})
    return redirect('login')

def login_view(request):
    if request.method == 'POST':
        # Gathering username and password
        username = request.POST['username']
        password = request.POST['password']
        # trying to log in using the given credentials
        user = authenticate(request, username=username, password=password)
        # case where the credentials are valid
        if user:
            otp = generate_otp() 
            otp_store[user.email] = {'otp': otp,'created_at': time.time(), 'data': {'username': username}}
            send_otp(user.email, otp)

            return render(request, 'accounts/verify_otp.html', {
                'email': user.email,
                'next_action': 'login'
            })
        # invalid credentials
        else:
            return render(request, 'accounts/login.html', {'error': 'Invalid credentials'})
    return render(request, 'accounts/login.html')

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        # case where the email is valid
        if User.objects.filter(email=email).exists():
            otp = generate_otp()
            otp_store[email] = {'otp': otp}
            send_otp(email, otp)
            return render(request, 'accounts/verify_otp.html', {'email': email, 'next_action': 'forgot_password'})
        # invalid email
        else:
            return render(request, 'accounts/forgot_password.html', {'error': 'Email not found'})
    return render(request, 'accounts/forgot_password.html')


def reset_password(request, email):
    if request.method == 'POST':
        password = request.POST['password']

        # Password Validation
        if not password_validation(password):
            return render(request, 'accounts/reset_password.html', {
                'email': email,
                'error': 'invalid password',
            })
        
        user = User.objects.get(email=email)
        user.set_password(password)
        user.save()
        return redirect('login')
    return render(request, 'accounts/reset_password.html', {'email': email})


def welcome(request, username):
    return render(request, 'accounts/welcome.html', {'username': username})

def home(request):
    return render(request, 'accounts/home.html')
