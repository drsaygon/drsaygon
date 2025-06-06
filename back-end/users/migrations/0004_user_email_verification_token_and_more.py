# Generated by Django 5.1.4 on 2025-01-13 13:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_alter_user_options_user_first_name_user_groups_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email_verification_token',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='email_verification_token_created',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='email_verified',
            field=models.BooleanField(default=False, help_text='Designates whether this user has verified their email address.', verbose_name='email verified'),
        ),
    ]
