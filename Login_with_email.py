#Create Login app............

#setting.py................
AUTH_USER_MODEL = 'Login.User'

#models.py........................
from django.db import models

#Create automatic one to one object profile
from django.db.models.signals import post_save
from django.dispatch import receiver
# Custom user & admin panel
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy




class MyUserManager(BaseUserManager):
    #custom login with email
    def _create_user(self, email, password, **extra_fields):

        #save user email and password
        if not email:
            raise ValueError("Email must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('SuperUser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('SuperUser must have is_superuser=True')
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approve', 'Approved'),
        ('disapprove', 'Disapproved'),
    )
    email = models.EmailField(unique=True, null=False)
    full_name = models.CharField(max_length=150, null=True, blank=True)
    country = models.CharField(max_length=200, null=True, blank=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    is_staff = models.BooleanField(
        gettext_lazy('staff Status'),
        default = False,
        help_text = gettext_lazy('Designates whether the user can login this site')
    )

    is_active = models.BooleanField(
        gettext_lazy('active'),
        default = True,
        help_text = gettext_lazy('Designates whether this user should be treated as active. Unselect this instead of deleting accounts')

    )

    USERNAME_FIELD = 'email'
    objects = MyUserManager()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

#views.py.......................
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponse, HttpResponseRedirect

#Authentication
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate

#Message Module
from django.contrib import messages

# Model & Form
from Login.models import Profile
from Login.forms import ProfileForm, RegistrationForm

#with django form.........
def registration(request):
    form = RegistrationForm()
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account create successfully")
            return HttpResponseRedirect(reverse('Login:signin'))
    return render(request, 'Login/registration.html', context={'form':form})

def signin(request):
    form = AuthenticationForm()
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return HttpResponseRedirect(reverse('Shop:home'))
    return render(request, 'Login/signin.html', context = {'form':form})

#Forms.py....................................
from django.forms import ModelForm
from Login.models import User
from django.contrib.auth.forms import UserCreationForm
from django import forms


class UserRegistrationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'address', 'phone', 'university_name', 'profile_picture']
        widgets = {
            'password': forms.PasswordInput(),
        }


class RegistrationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('email', 'password',)
        #fields = ('email', 'password_1', 'password_2',)



#django template..........
def registration(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        full_name = request.POST.get('full_name')
        country = request.POST.get('country')
        address = request.POST.get('address')
        phone = request.POST.get('phone')
        github = request.POST.get('github')
        gender = request.POST.get('Gender')
        birth_date= request.POST.get('birth_date')
        university = request.POST.get('university')
        profile_picture = request.FILES.get('profile_picture')

        if User.objects.filter(email=email).exists():
            error_message = "This email is already registered. Please use a different email."
            return render(request, 'Login/registration.html', {'error_message': error_message})
        
      user = User(email=email, full_name=full_name,
                          country=country,address=address, phone=phone, university=university,
                          gender=gender, birth_date=birth_date,  github=github, profile_picture=profile_picture)
        user.set_password(password)
        
        # Set the user as inactive until they verify their email
        user.is_active = True

        # Save the token and expiration time in the user's model
        token = get_random_string(length=64)
        print("Token:", token)

        # Save the token in the user's model
        user.verification_token = token
        user.save()
      
        messages.success(request, success_message)
        return HttpResponseRedirect(reverse('home'))

    return render(request, 'Login/registration.html')

def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Use the 'authenticate' function from 'django.contrib.auth'
        user = authenticate(request, email=email, password=password)

        if user is not None:
            print("User is not None")  # For debugging

            # Check if the user is authenticated before logging them in
            if user.email_verify == True:
                login(request, user)
                messages.success(request, "You are logged in successfully")
                return HttpResponseRedirect(reverse('home'))
            else:
                messages.error(request, "Your account is inactive. Please check your email.")
        else:
            print("User is None")  # For debugging
            messages.error(request, "Incorrect email or password. Please try again.")

    return render(request, 'Login/login.html')
