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
    path('twitter/getrequesttoken/', views.GetTwitterRequestToken.as_view()),
    path('twitter/getusertoken/', views.GetTwitterUserToken.as_view())
]
