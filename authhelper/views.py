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

from rest_framework_social_oauth2.oauth2_backends import KeepRequestCore
from rest_framework_social_oauth2.oauth2_endpoints import SocialTokenServer

from social_core.backends.oauth import BaseOAuth1, BaseOAuth2
from social_core.exceptions import (
    AuthAlreadyAssociated, NotAllowedToDisconnect)
from social_django.utils import load_backend, load_strategy

from authhelper.models import (
    UserEmail, UserEmailValidation, ResetPasswordToken)
from authhelper.serializers import (
    RegisterSerializer,
    EmailValidateSerializer,
    ForgotPasswordInitiateSerializer,
    ForgotPasswordSerializer,
    ConvertTokenSerializer,
    AddEmailSerializer,
    UserEmailSerilaizer,
    UserSocialAuthSerializer,
    UserPasswordSerializer
)
from authhelper.utils import (
    get_token_user_email_data,
    get_twitter_request_token,
    get_twitter_user_auth_token
)
from authhelper.tasks import (
    task_send_validation_email, task_send_password_reset_email)


SPECIAL_SCOPES = ['baza-beta', 'ekata-beta']


def user_has_access(user, asked_scopes):
    for scope in asked_scopes:
        if scope in SPECIAL_SCOPES:
            user_special_scopes = user.userprofile.get_special_scopes()
            if scope not in user_special_scopes:
                return False
    return True


class LoginUserView(views.APIView):
    """
    This view will be used for user login
    """

    def post(self, request, format=None):
        response = TokenView.as_view()(request._request)
        response_data = json.loads(response.content)
        if response_data.get('access_token'):
            AccessToken = get_access_token_model()
            user = AccessToken.objects.get(
                token=response_data.get('access_token')).user
            if user_has_access(user, request.data.getlist('scope')):
                response_data['email_verified'] = False
                response_data['username'] = user.username
                email = user.emails.filter(primary=True)
                if len(email):
                    response_data['email_verified'] = email[0].verified
                    response_data['email'] = email[0].email
            else:
                return Response(
                    {'error_description':
                        'You don\'t have access to this site'},
                    status=status.HTTP_403_FORBIDDEN
                )
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

    def get_token_user_response(
            self, email_data, token_data, validated_data, user):
        if email_data['access_token_exist']:
            if email_data['email_exist']:
                token_data['email'] = email_data['user'].email
                token_data['email_verified'] = False
                if email_data['user_email_object_exist']:
                    token_data['email_verified'] = email_data[
                        'useremail'].verified
                else:
                    UserEmail.objects.create(
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
            token_data['username'] = user.username
            return Response(token_data)
        return Response(
            {'access_token_exist': email_data['access_token_exist']})

    def post(self, request, *args, **kwargs):
        serializer = ConvertTokenSerializer(data=request.data)
        if serializer.is_valid():
            request._request.POST = request._request.POST.copy()
            for key, value in request.data.items():
                request._request.POST[key] = value
            url, headers, body, res_status = self.create_token_response(
                request._request)
            if res_status == 200:
                access_token = json.loads(body).get('access_token', None)
                AccessToken = get_access_token_model()
                user = AccessToken.objects.get(token=access_token).user
                if access_token and user_has_access(
                        user, request.data.getlist('scope')):
                    email_data = get_token_user_email_data(access_token)
                    return self.get_token_user_response(
                        email_data, json.loads(body),
                        serializer.validated_data, user)
                else:
                    return Response(
                        {'error_description':
                         'You don\'t have access to this site'},
                        status=status.HTTP_403_FORBIDDEN
                    )
            return Response(json.loads(body), status=res_status)
        return Response(
            serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
                if serializer.validated_data.get('from_social') else False
            )
            if serializer.validated_data.get('email_validation') != 'none':
                task_send_validation_email.delay(
                    serializer.validated_data['email'],
                    serializer.validated_data['initiator_use_ssl'],
                    serializer.validated_data['initiator_site'],
                    serializer.validated_data['initiator_email']
                )
            return Response(UserEmailSerilaizer(useremail).data)
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


class UpdateSpecialUserScope(views.APIView):
    """
    This view will be used to add or remove special scopes from
    an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def add_special_scope(self, scope, user):
        userprofile = user.userprofile
        if scope not in userprofile.get_special_scopes():
            user_special_scopes = userprofile.get_special_scopes()
            user_special_scopes.append(scope.strip())
            userprofile.special_scopes = ','.join(user_special_scopes)
            userprofile.save()

    def remove_special_scope(self, scope, user):
        userprofile = user.userprofile
        if scope in userprofile.get_special_scopes():
            user_special_scopes = userprofile.get_special_scopes()
            user_special_scopes.remove(scope.strip())
            userprofile.special_scopes = ','.join(user_special_scopes)
            userprofile.save()

    def post(self, request, format=None):
        update_type = request.data.get('update_type')
        if update_type == 'add':
            self.add_special_scope(
                request.data.get('scope'),
                User.objects.get(username=request.data.get('username'))
            )
        if update_type == 'remove':
            self.remove_special_scope(
                request.data.get('scope'),
                User.objects.get(username=request.data.get('username'))
            )
        return Response()


class GetUserEmailsView(views.APIView):
    """
    This view will be used for getting the list of emails of an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def get(self, request, format=None):
        AccessToken = get_access_token_model()
        user = AccessToken.objects.get(
            token=request.data['access_token']).user
        emails = user.emails.all()
        serializer = UserEmailSerilaizer(emails, many=True)
        return Response(serializer.data)


class DeleteUserEmailView(views.APIView):
    """
    This view will be used to delete an users email
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        AccessToken = get_access_token_model()
        email = UserEmail.objects.get(id=request.data['email_id'])
        user = AccessToken.objects.get(
            token=request.data['access_token']).user
        if user == email.user and not email.primary:
            email.delete()
            return Response(request.data['email_id'])
        return Response(
            {"error": "You can't delete this email id"},
            status=status.HTTP_400_BAD_REQUEST)


class UpdateUserEmailView(views.APIView):
    """
    This view will be used to set primary email of an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        AccessToken = get_access_token_model()
        email = UserEmail.objects.get(id=request.data['email_id'])
        user = AccessToken.objects.get(
            token=request.data['access_token']).user
        if user == email.user:
            if email.verified:
                for e in user.emails.all():
                    e.primary = False
                    e.save()
                email.primary = True
                email.save()
                return Response(request.data['email_id'])
            return Response({
                'error': "You can't set primary until email is verified"
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {"error": "You can't update this email id"},
            status=status.HTTP_400_BAD_REQUEST)


class GetUserSocialAuths(views.APIView):
    """
    This view will be used to get all social account linked to
    an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def get(self, request, format=None):
        AccessToken = get_access_token_model()
        user = AccessToken.objects.get(
            token=request.data['access_token']).user
        social_auths = user.social_auth.all()
        serializer = UserSocialAuthSerializer(
            social_auths, many=True)
        return Response(serializer.data)


class ConnectSocialAuth(views.APIView):
    """
    This view will be used to link a social account to an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        provider = request.data['provider']
        AccessToken = get_access_token_model()
        authed_user = AccessToken.objects.get(
            token=request.data['access_token']).user
        strategy = load_strategy(request._request)
        backend = load_backend(
            strategy=strategy, name=provider, redirect_uri=None)

        if isinstance(backend, BaseOAuth1):
            token = {
                'oauth_token': request.data['oauth_token'],
                'oauth_token_secret': request.data['oauth_token_secret'],
            }
        if isinstance(backend, BaseOAuth2):
            token = request.data['provider_access_token']

        try:
            user = backend.do_auth(token, user=authed_user)
            social_auths = user.social_auth.all()
            serializer = UserSocialAuthSerializer(
                social_auths, many=True)
            return Response(serializer.data)
        except AuthAlreadyAssociated:
            return Response(
                {"error": "This social account is"
                    " associated with another account"},
                status=status.HTTP_400_BAD_REQUEST
            )


class DisconnectSocialAuth(views.APIView):
    """
    This view will be used to disconnect a social account from an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        provider = request.data['provider']
        association_id = request.data['association_id']
        AccessToken = get_access_token_model()
        authed_user = AccessToken.objects.get(
            token=request.data['access_token']).user
        strategy = load_strategy(request._request)
        backend = load_backend(
            strategy=strategy, name=provider, redirect_uri=None)
        try:
            backend.disconnect(
                user=authed_user,
                name=provider,
                association_id=association_id
            )
            social_auths = authed_user.social_auth.all()
            serializer = UserSocialAuthSerializer(
                social_auths, many=True)
            return Response(serializer.data)
        except NotAllowedToDisconnect:
            return Response({
                "error": "You can't disconnect this social account"
                " because this is your only method to login"
            }, status=status.HTTP_400_BAD_REQUEST)


class SetUserPassword(views.APIView):
    """
    This view will be used to set new password for an user
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        AccessToken = get_access_token_model()
        authed_user = AccessToken.objects.get(
            token=request.data['access_token']).user
        serializer = UserPasswordSerializer(
            data=request.data, context={'user': authed_user}
        )
        if serializer.is_valid():
            authed_user.set_password(
                serializer.validated_data['new_password_1'])
            authed_user.save()
            return Response({
                'status': 'success'
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckPasswordView(views.APIView):
    """
    This api checks wheather inputed password matches with users
    password
    """
    authentication_classes = (OAuth2Authentication, )
    permission_classes = (TokenHasReadWriteScope, )

    def post(self, request, format=None):
        AccessToken = get_access_token_model()
        authed_user = AccessToken.objects.get(
            token=request.data['access_token']).user
        password_valid = authed_user.check_password(
            request.data['password']
        )
        if password_valid:
            return Response({
                'password_valid': password_valid
            })
        return Response({
            'password_valid': password_valid
        }, status=status.HTTP_400_BAD_REQUEST)
