from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
# encoding
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str

# resetpassword generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# email send
from django.core.mail import send_mail

from auth import settings




# Create your views here.
def home(request):
    return render(request,'authapp/home.html')

def login_user(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        
        if username =="":
            messages.error(request,'Username is required')
        elif password =="":
            messages.error(request,'Password is required')
        
        user = authenticate(username = username, password = password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials')
    return render(request, 'authapp/login.html')

def register_user(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        getUsername = User.objects.filter(username = username)
        getEmail = User.objects.filter(email = email)
        
        error_message =""
        if first_name == "":
            error_message = "First name is required"
        elif last_name =="":
            error_message = "Last name is required"
        elif username =="":
            error_message = "Username is required"
        elif email =="":
            error_message = "Email is required"
        elif password =="":
            error_message = "Password is required"
        elif password != confirm_password:
            error_message = "password not matched"
        elif getUsername.exists():
            error_message = "Username already taken"
        elif getEmail.exists():
            error_message="This email already have an account"


        if not error_message:
            users = User.objects.create_user(username=username,email=email,password=password,first_name=first_name,last_name=last_name)
            if users:
                messages.success(request, "User created successfully.")
                return redirect('login')
        else:
            return render(request,'authapp/register.html',{'messages':error_message, 'first_name':first_name,'last_name':last_name,'username':username,'email':email})
        
    return render(request, 'authapp/register.html')

@login_required(login_url='login')
def dashboard_user(request):
    return render(request,'authapp/dashboard.html')

def logout_user(request):
    logout(request)
    return redirect('login')

@login_required(login_url='login')
def changepassword_user(request):
    if request.method == "POST":
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        user = User.objects.get(id= request.user.id)
        query = user.check_password(current_password)
        if new_password != confirm_password:
            messages.error(request,'Confirmation password not matched.')
        elif query != True:
            messages.error(request,'Current password not matched')
        else:
            user = User.objects.get(id= request.user.id)
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Password Changes successfully.')
            return redirect('login')
    return render(request,'authapp/change_password.html')


def reset_password(request):
    if request.method == "POST":
        email = request.POST['email']
        if email =="":
            messages.error(request,"Email is required.")
        user = User.objects.filter(email= email)
        if user.exists():
            current_site = get_current_site(request)
            emai_subject = 'Rest your password'
            message = render_to_string('authapp/reset_password_link.html',{
                'domain':current_site,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(user[0]),
            })
            send_mail(
                emai_subject,
                message, 
                settings.EMAIL_HOST_USER,
                [email] 
            )
            
    return render(request,'authapp/reset_password.html')

def reset_password_confirm(request,uidb64,token):
    user_id = force_str(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk = user_id)
    if not PasswordResetTokenGenerator().check_token(user, token):
        messages.error(request,'Password reset link is invalid.')
        return redirect('resetPassword')
    if request.method == "POST":
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        if new_password != confirm_password:
            messages.error(request,'Confirmation password not matched.')
        user.set_password(new_password)
        user.save()
        messages.success(request,'Password reset successful, Login now.')
        return redirect('login')
    return render(request,'authapp/reset_password_confirm.html')