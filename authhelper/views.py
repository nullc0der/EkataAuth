import json

from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

from rest_framework import views, status
from rest_framework.response import Response
from oauth2_provider.contrib.rest_framework import (
    OAuth2Authentication,
    TokenHasReadWriteScope
)
from oauth2_provider.models import get_access_token_model
from oauth2_provider.views import TokenView

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)
from authhelper.serializers import (
    RegisterSerializer,
    EmailValidateSerializer,
    ForgotPasswordInitiateSerializer,
    ForgotPasswordSerializer
)
from authhelper.tasks import (
    task_send_validation_email, task_send_password_reset_email)


# Create your views here.


class LoginUserView(views.APIView):
    """
    TODO: Add documentation
    This API needs some refactoring and logic change!
    """

    def post(self, request, format=None):
        response = TokenView.as_view()(request._request)
        response_data = json.loads(response.content)
        if response_data.get('access_token'):
            response_data['email_verified'] = False
            token_user = get_access_token_model().objects.get(
                token=response_data.get('access_token')
            ).user
            email = token_user.emails.filter(primary=True)
            if len(email):
                response_data['email_verified'] = email[0].verified
                response_data['email'] = email[0].email
        return Response(response_data, response.status_code)


class RegisterUserView(views.APIView):
    """
    This view will be used for registering a user
    TODO: Add documentation
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            with transaction.atomic():
                user = User.objects.create_user(
                    username=serializer.validated_data.get('username'),
                    password=serializer.validated_data.get('password')
                )
                useremail = UserEmail.objects.create(
                    user=user,
                    email=serializer.validated_data.get('email'),
                    primary=True
                )
                if serializer.validated_data.get('email_validation') != 'none':
                    task_send_validation_email.delay(
                        serializer.validated_data['email'],
                        serializer.validated_data['initiator_use_ssl'],
                        serializer.validated_data['initiator_site'],
                        serializer.validated_data['initiator_email']
                    )
            return Response({
                'user': user.username,
                'email': useremail.email
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ValidateEmailView(views.APIView):
    """
    This view will be used for validating an email
    TODO: Add documentation
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        serializer = EmailValidateSerializer(data=request.data)
        if serializer.is_valid():
            useremailvalidation = UserEmailValidation.objects.get(
                validation_key=serializer.validated_data.get('validation_key')
            )
            useremailvalidation.useremail.verified = True
            useremailvalidation.useremail.save()
            useremailvalidation.delete()
            return Response({
                'status': 'success',
                'validation_key':
                    ['Email verified successfully, please login to continue.']
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckEmailVerifiedView(views.APIView):
    """
    This view will be used to check wheather an email
    id is verified
    TODO: Add documentation
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        data = {
            'email_verified': False
        }
        try:
            token_user = get_access_token_model().objects.get(
                token=request.data.get('token')
            ).user
            email = token_user.emails.filter(primary=True)
            if len(email):
                data['email_verified'] = email[0].verified
                data['email'] = email[0].email
            return Response(data)
        except ObjectDoesNotExist:
            return Response(data, status=status.HTTP_404_NOT_FOUND)


class InitiateForgotPasswordView(views.APIView):
    """
    This view will initiate the forgot password flow
    TODO: Add documentation
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        serializer = ForgotPasswordInitiateSerializer(data=request.data)
        if serializer.is_valid():
            task_send_password_reset_email.delay(
                serializer.validated_data['email'],
                serializer.validated_data['initiator_use_ssl'],
                serializer.validated_data['initiator_site'],
                serializer.validated_data['initiator_email']
            )
            return Response({
                'status': 'success'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(views.APIView):
    """
    This view reset an users password
    TODO: Add documentation
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            resetpasswordtoken = ResetPasswordToken.objects.get(
                token=serializer.validated_data.get('reset_token')
            )
            resetpasswordtoken.user.set_password(serializer.validated_data.get(
                'password'))
            resetpasswordtoken.user.save()
            resetpasswordtoken.delete()
            return Response({
                'status': 'success'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
