from datetime import timedelta

from django.contrib.auth.models import User
from django.utils.timezone import now

from rest_framework import serializers

from oauth2_provider.models import get_access_token_model

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField()
    password1 = serializers.CharField()
    email = serializers.EmailField()
    email_validation = serializers.CharField()
    initiator_site = serializers.CharField()
    initiator_use_ssl = serializers.BooleanField()
    initiator_email = serializers.EmailField()

    def validate_username(self, value):
        try:
            User.objects.get(username=value)
            raise serializers.ValidationError(
                'Username is taken'
            )
        except User.DoesNotExist:
            return value

    def validate_email(self, value):
        try:
            UserEmail.objects.get(
                email=value
            )
            raise serializers.ValidationError(
                'Someone already used this email id'
            )
        except UserEmail.DoesNotExist:
            return value

    def validate(self, data):
        if data['password'] != data['password1']:
            raise serializers.ValidationError('Passwords are not matching')
        return data


class EmailValidateSerializer(serializers.Serializer):
    validation_key = serializers.CharField()

    def validate_validation_key(self, value):
        try:
            useremailvalidation = UserEmailValidation.objects.get(
                validation_key=value
            )
            if useremailvalidation.created_on + timedelta(days=1) > now():
                return value
            raise serializers.ValidationError('Validation key expired')
        except UserEmailValidation.DoesNotExist:
            raise serializers.ValidationError('Invalid validation key')


class ForgotPasswordInitiateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    initiator_site = serializers.CharField()
    initiator_use_ssl = serializers.BooleanField()
    initiator_email = serializers.EmailField()

    def validate_email(self, value):
        try:
            UserEmail.objects.get(
                email=value
            )
            return value
        except UserEmail.DoesNotExist:
            raise serializers.ValidationError(
                'No user associated with this email'
            )


class ForgotPasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    password1 = serializers.CharField()
    reset_token = serializers.CharField()

    def validate(self, data):
        try:
            resetpasswordtoken = ResetPasswordToken.objects.get(
                token=data['reset_token'])
            if resetpasswordtoken.created_on + timedelta(days=1) < now():
                raise serializers.ValidationError('Reset url expired')
        except ResetPasswordToken.DoesNotExist:
            raise serializers.ValidationError('Reset url is invalid')
        if data['password'] != data['password1']:
            raise serializers.ValidationError('Passwords are not matching')
        return data


class ConvertTokenSerializer(serializers.Serializer):
    token = serializers.CharField()
    email_validation = serializers.CharField()
    initiator_site = serializers.CharField()
    initiator_use_ssl = serializers.BooleanField()
    initiator_email = serializers.EmailField()


class AddEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    access_token = serializers.CharField()
    initiator_site = serializers.CharField()
    initiator_use_ssl = serializers.BooleanField()
    initiator_email = serializers.EmailField()
    from_social = serializers.BooleanField()

    def validate_access_token(self, value):
        AccessToken = get_access_token_model()
        try:
            AccessToken.objects.get(token=value)
            return value
        except AccessToken.DoesNotExist:
            raise serializers.ValidationError(
                'Access token is invalid'
            )

    def validate_email(self, value):
        try:
            UserEmail.objects.get(
                email=value
            )
            raise serializers.ValidationError(
                'This email is associated with another account'
            )
        except UserEmail.DoesNotExist:
            return value


class UserEmailSerilaizer(serializers.ModelSerializer):
    class Meta:
        model = UserEmail
        fields = ('id', 'email', 'primary', 'verified')