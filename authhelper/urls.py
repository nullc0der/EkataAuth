from django.urls import path

from authhelper import views

urlpatterns = [
    path('loginuser/', views.LoginUserView.as_view()),
    path('registeruser/', views.RegisterUserView.as_view()),
    path('validateemail/', views.ValidateEmailView.as_view()),
    path('isemailverified/', views.CheckEmailVerifiedView.as_view()),
    path('initiateforgotpassword/',
         views.InitiateForgotPasswordView.as_view()),
    path('forgotpassword/', views.ForgotPasswordView.as_view()),
    path('converttoken/', views.ConvertTokenView.as_view()),
    path('addemail/', views.AddEmailView.as_view()),
    path('deleteemail/', views.DeleteUserEmailView.as_view()),
    path('useremails/', views.GetUserEmailsView.as_view()),
    path('updateemail/', views.UpdateUserEmailView.as_view()),
    path('twitter/getrequesttoken/', views.GetTwitterRequestToken.as_view()),
    path('twitter/getusertoken/', views.GetTwitterUserToken.as_view()),
    path('updateuserscope/', views.UpdateSpecialUserScope.as_view()),
    path('getsocialauths/', views.GetUserSocialAuths.as_view()),
    path('connectsocialauth/', views.ConnectSocialAuth.as_view()),
    path('disconnectsocialauth/', views.DisconnectSocialAuth.as_view()),
    path('setpassword/', views.SetUserPassword.as_view()),
    path('checkpassword/', views.CheckPasswordView.as_view()),
    path('resendvalidationemail/', views.ResendValidationEmailView.as_view()),
    path('userhaspassword/', views.CheckUserHasUsablePassword.as_view()),
    path('usersocialphoto/', views.UserSocialProfilePhoto.as_view()),
    path('usersocialscopes/', views.UserSocialScopes.as_view()),
    path('usersocialcredentials/', views.UserSocialCredentials.as_view())
]
