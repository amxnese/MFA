import secrets
import smtplib
from email.message import EmailMessage
from os import getenv
import re

PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z0-9]).{10,}$')

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

def send_otp(user_email, otp):
    source_email = getenv('EMAIL_USER')
    email_pass = getenv('EMAIL_PASS')
    destination = user_email

    # Forming the msg
    msg = EmailMessage()
    msg['Subject'] = 'OTP Verification'
    msg['From'] = source_email
    msg['To'] = destination
    msg.set_content(f'Your OTP is : {otp}')

    # trying to send the email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(source_email, email_pass)
        server.send_message(msg)
        print('email sent')
    # email not sent
    except:
        print('there was and error trying to send the email please try again')
    # quiting the server
    finally:
        server.quit()

def password_validation(password):
    return PASSWORD_REGEX.match(password)