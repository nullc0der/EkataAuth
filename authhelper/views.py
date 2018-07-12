import json

from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

from rest_framework import views, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from oauth2_provider.contrib.rest_framework import (
    OAuth2Authentication,
    TokenHasReadWriteScope
)
from oauth2_provider.models import get_access_token_model
from oauth2_provider.views import TokenView
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin
from oauth2_provider.settings import oauth2_settings

from rest_framework_social_oauth2.oauth2_backends import KeepRequestCore
from rest_framework_social_oauth2.oauth2_endpoints import SocialTokenServer

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)
from authhelper.serializers import (
    RegisterSerializer,
    EmailValidateSerializer,
    ForgotPasswordInitiateSerializer,
    ForgotPasswordSerializer,
    ConvertTokenSerializer,
    AddEmailSerializer
)
from authhelper.utils import (
    get_token_user_email_data,
    get_twitter_request_token,
    get_twitter_user_auth_token
)
from authhelper.tasks import (
    task_send_validation_email, task_send_password_reset_email)


# Create your views here.


class LoginUserView(views.APIView):
    """
    This view will be used for user login
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


class ConvertTokenView(OAuthLibMixin, views.APIView):
    """
    This view will be used to login and register an user
    using social sites
    """

    server_class = SocialTokenServer
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = KeepRequestCore
    permission_classes = (AllowAny, )

    def get_token_user_response(self, email_data, token_data, validated_data):
        if email_data['access_token_exist']:
            if email_data['email_exist']:
                token_data['email'] = email_data['user'].email
                token_data['email_verified'] = False
                if email_data['user_email_object_exist']:
                    token_data['email_verified'] = email_data[
                        'useremail'].verified
                else:
                    useremail = UserEmail.objects.create(
                        user=email_data['user'],
                        email=email_data['user'].email,
                        primary=True
                    )
                    if validated_data.get('email_validation') != 'none':
                        task_send_validation_email.delay(
                            email_data['user'].email,
                            validated_data['initiator_use_ssl'],
                            validated_data['initiator_site'],
                            validated_data['initiator_email']
                        )
            token_data['access_token_exist'] = email_data['access_token_exist']
            token_data['email_exist'] = email_data['email_exist']
            return Response(token_data)
        return Response(
            {'access_token_exist': email_data['access_token_exist']})

    def post(self, request, *args, **kwargs):
        serializer = ConvertTokenSerializer(data=request.data)
        if serializer.is_valid():
            request._request.POST = request._request.POST.copy()
            for key, value in request.data.items():
                request._request.POST[key] = value
            url, headers, body, status = self.create_token_response(
                request._request)
            if status == 200:
                email_data = get_token_user_email_data(
                    json.loads(body)['access_token']
                )
                return self.get_token_user_response(
                    email_data, json.loads(body), serializer.validated_data)
            return Response(json.loads(body), status=status)
        return Response(serializer.errors, status=400)


class AddEmailView(views.APIView):
    """
    This view will be used for adding email for an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        serializer = AddEmailSerializer(data=request.data)
        if serializer.is_valid():
            AccessToken = get_access_token_model()
            user = AccessToken.objects.get(
                token=serializer.validated_data.get('access_token')).user
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


class GetTwitterRequestToken(views.APIView):
    """
    This view will be used for getting a request token from twitter
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        res = get_twitter_request_token(request.data['callback_uri'])
        if res.status_code == 200:
            data = {}
            for d in res.content.decode('utf-8').split('&'):
                key, val = d.split('=')
                data[key] = val
            return Response(data)
        return Response(
            {'error': 'Server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetTwitterUserToken(views.APIView):
    """
    This view will be used to get user access token and secret from twitter
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        res = get_twitter_user_auth_token(
            request.data['oauth_token'], request.data['oauth_verifier'])
        if res.status_code == 200:
            data = {}
            for d in res.content.decode('utf-8').split('&'):
                key, val = d.split('=')
                data[key] = val
            return Response(data)
        return Response(
            {'error': 'Server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
