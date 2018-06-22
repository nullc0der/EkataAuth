from __future__ import absolute_import, unicode_literals

from celery import shared_task

from authhelper.utils import send_validation_email, send_password_reset_email


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
