from __future__ import absolute_import, unicode_literals

from celery import shared_task, task

from django.core.management import call_command

from authhelper.utils import (
    send_validation_email,
    send_password_reset_email,
    save_disposable_email_domain_list
)


@shared_task
def task_send_validation_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email):
    return send_validation_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email)


@shared_task
def task_send_password_reset_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email):
    return send_password_reset_email(
        email_id, initiator_use_ssl, initiator_site, initiator_email)


@task
def task_clear_expired_access_tokens():
    call_command('cleartokens')


@task
def task_save_disposable_email_domain_list():
    return save_disposable_email_domain_list()
