from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from datetime import datetime, timedelta
from django.utils import timezone
from .tokens import email_verification_token_generator

def send_verification_email(user, domain):
    subject = 'Verifique seu endereço de email'
    
    # Gerar token e salvar timestamp
    token = email_verification_token_generator.make_token(user)
    user.email_verification_token = token
    user.email_verification_token_created = timezone.now()
    user.save()
    
    context = {
        'user': user,
        'domain': domain,
        'token': token,
    }
    
    html_content = render_to_string('email/verification_email.html', context)
    text_content = strip_tags(html_content)
    
    email = EmailMultiAlternatives(
        subject,
        text_content,
        settings.DEFAULT_FROM_EMAIL,
        [user.email]
    )
    email.attach_alternative(html_content, "text/html")
    return email.send()

def is_verification_token_expired(token_created):
    if not token_created:
        return True
    expiry_date = token_created + timedelta(minutes=30)
    return timezone.now() > expiry_date