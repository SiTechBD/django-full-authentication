from django.urls import path
from authapp.views import *

urlpatterns = [
    path('', home, name='home'),
    path('login', login_user, name='login'),
    path('register', register_user, name='register'),
    path('dashboard', dashboard_user, name='dashboard'),
    path('logout', logout_user, name='logout'),
    path('changepassword', changepassword_user, name='changepassword'),
    path('resetPassword', reset_password, name='resetPassword'),
    path('resetPasswordConfirm/<uidb64>/<token>', reset_password_confirm, name='reset_password_confirm'),
]