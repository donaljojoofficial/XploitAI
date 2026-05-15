"""
Authentication views for XploitAI.
Handles user registration, login, logout, and password management.
"""

from django import forms
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.core.cache import cache
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpRequest
from django.views.decorators.http import require_POST
from django.contrib import messages
from django.urls import reverse
import threading
import random


class RegistrationForm(forms.ModelForm):
    """User registration form with password confirmation."""
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
            'placeholder': 'Password'
        }),
        min_length=8,
        help_text="Password must be at least 8 characters long."
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
            'placeholder': 'Confirm Password'
        }),
        label="Confirm Password"
    )
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name')
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
                'placeholder': 'Username',
                'required': True
            }),
            'email': forms.EmailInput(attrs={
                'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
                'placeholder': 'Email Address',
                'required': True
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
                'placeholder': 'First Name (Optional)'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
                'placeholder': 'Last Name (Optional)'
            }),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm:
            if password != password_confirm:
                raise forms.ValidationError("Passwords do not match.")
        
        # Check if username already exists
        if User.objects.filter(username=cleaned_data.get('username')).exists():
            raise forms.ValidationError("Username already taken.")
        
        # Check if email already exists
        if User.objects.filter(email=cleaned_data.get('email')).exists():
            raise forms.ValidationError("Email already registered.")
        
        return cleaned_data
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            # newly created users start inactive until email confirmed
            user.is_active = False
            user.save()
        return user


class LoginForm(forms.Form):
    """User login form."""
    
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
            'placeholder': 'Username',
            'autocomplete': 'username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-accent',
            'placeholder': 'Password',
            'autocomplete': 'current-password'
        })
    )
    remember_me = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'rounded'
        }),
        label="Remember me"
    )
    
    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')
        
        if username and password:
            self.user = authenticate(username=username, password=password)
            if self.user is None:
                pending_user = User.objects.filter(username=username).first()
                if pending_user and check_password(password, pending_user.password) and not pending_user.is_active:
                    raise forms.ValidationError("Your account is pending administrator approval.")
                raise forms.ValidationError("Invalid username or password.")
        
        return cleaned_data


def _add_to_default_group(user: User) -> None:
    """Assign a newly registered user to the default 'User' group."""
    group, _ = Group.objects.get_or_create(name='User')
    user.groups.add(group)


def send_activation_email(user: User, request: HttpRequest) -> None:
    """Send account activation email asynchronously."""
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    activation_link = request.build_absolute_uri(
        reverse('activate', kwargs={'uidb64': uid, 'token': token})
    )
    subject = 'Activate your XploitAI account'
    message = render_to_string('dashboard/auth/activation_email.txt', {
        'user': user,
        'activation_link': activation_link,
    })
    # send in background thread to avoid delaying response
    threading.Thread(target=send_mail, args=(subject, message, None, [user.email])).start()


def register(request: HttpRequest) -> HttpResponse:
    """Handle user registration and queue the account for administrator approval."""
    
    if request.user.is_authenticated:
        return redirect('dashboard_index')
    
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            _add_to_default_group(user)
            messages.success(request, "Account request submitted. An administrator must approve it before you can log in.")
            return redirect('login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'dashboard/auth/register.html', {'form': form})


def login_view(request: HttpRequest) -> HttpResponse:
    """Handle user login (only active users permitted)."""
    
    if request.user.is_authenticated:
        return redirect('dashboard_index')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            user = form.user
            if not user.is_active:
                messages.error(request, "Your account is pending administrator approval.")
                return render(request, 'dashboard/auth/login.html', {'form': form})
            login(request, user)
            
            # Set session timeout if "remember me" is checked
            if form.cleaned_data.get('remember_me'):
                request.session.set_expiry(86400 * 30)  # 30 days
            
            messages.success(request, f"Welcome back, {user.username}!")
            next_url = request.GET.get('next', 'dashboard_index')
            return redirect(next_url)
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, str(error))
    else:
        form = LoginForm()
    
    return render(request, 'dashboard/auth/login.html', {'form': form})


@login_required(login_url='login')
def logout_view(request: HttpRequest) -> HttpResponse:
    """Handle user logout."""
    
    if request.method == 'POST':
        username = request.user.username
        logout(request)
        messages.success(request, f"Goodbye, {username}! You have been logged out.")
        return redirect('login')
    
    return redirect('login')


def activate(request: HttpRequest, uidb64: str, token: str) -> HttpResponse:
    """Email activation is disabled; new accounts require administrator approval."""
    messages.info(request, "Account activation is handled by an administrator. Please wait for approval before logging in.")
    return redirect('login')


def password_reset_request(request: HttpRequest) -> HttpResponse:
    """Handle request for a password reset code."""
    if request.user.is_authenticated:
        return redirect('dashboard_index')
        
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Rate limiting: limit to 1 request per 2 minutes per email
        cooldown_key = f"pwd_reset_cooldown_{email}"
        if cache.get(cooldown_key):
            messages.success(request, "If an account with that email exists, a code and a link to reset your password have been sent.")
            return redirect('login')
            
        cache.set(cooldown_key, True, timeout=120)

        user = User.objects.filter(email=email, is_active=True).first()
        if user:
            code = str(random.randint(100000, 999999))
            cache.set(f"reset_code_{user.pk}", code, timeout=900) # 15 mins
            
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            verify_url = request.build_absolute_uri(
                reverse('password_reset_verify', kwargs={'uidb64': uid})
            )

            subject = 'Your Password Reset Code'
            message = render_to_string('dashboard/auth/password_reset_email.txt', {
                'code': code,
                'verify_url': verify_url,
            })
            threading.Thread(target=send_mail, args=(subject, message, None, [email])).start()
            
        # Always show the same message to prevent email enumeration
        messages.success(request, "If an account with that email exists, a code and a link to reset your password have been sent.")
        return redirect('login')
        
    return render(request, 'dashboard/auth/password_reset_request.html')


def password_reset_verify(request: HttpRequest, uidb64: str) -> HttpResponse:
    """Verify the 6-digit code and reset password."""
    if request.user.is_authenticated:
        return redirect('dashboard_index')
        
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is None:
        messages.error(request, "The password reset link is invalid or has expired.")
        return redirect('password_reset')
        
    if request.method == 'POST':
        code = request.POST.get('code')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        cached_code = cache.get(f"reset_code_{user.pk}")
        
        if not cached_code or cached_code != code:
            messages.error(request, "Invalid or expired reset code.")
            return render(request, 'dashboard/auth/password_reset_verify.html', {'uidb64': uidb64, 'email': user.email})
            
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'dashboard/auth/password_reset_verify.html', {'uidb64': uidb64, 'email': user.email})
            
        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long.")
            return render(request, 'dashboard/auth/password_reset_verify.html', {'uidb64': uidb64, 'email': user.email})
            
        user.set_password(new_password)
        user.save()
        cache.delete(f"reset_code_{user.pk}")
        if 'reset_email' in request.session:
            del request.session['reset_email']
        messages.success(request, "Password has been reset successfully. You can now log in.")
        return redirect('login')
            
    return render(request, 'dashboard/auth/password_reset_verify.html', {'uidb64': uidb64, 'email': user.email})


# Role-based decorators

def group_required(group_name: str):
    def in_group(u):
        return u.is_authenticated and u.groups.filter(name=group_name).exists()
    return user_passes_test(in_group, login_url='login')

def admin_required(view_func):
    return user_passes_test(
        lambda u: (
            u.is_authenticated and (
                u.is_superuser
                or u.is_staff
                or u.groups.filter(name='Admin').exists()
            )
        ),
        login_url='login'
    )(view_func)


@login_required(login_url='login')
@admin_required
def user_management(request: HttpRequest) -> HttpResponse:
    """Admin page for approving pending user registrations."""
    pending_users = User.objects.filter(is_active=False, is_superuser=False).order_by('date_joined')
    active_users = User.objects.filter(is_active=True).order_by('username')
    return render(request, 'dashboard/auth/user_management.html', {
        'pending_users': pending_users,
        'active_users': active_users,
    })


@login_required(login_url='login')
@admin_required
@require_POST
def approve_user(request: HttpRequest, user_id: int) -> HttpResponse:
    """Approve a pending user so they can log in."""
    user = get_object_or_404(User, pk=user_id, is_active=False)
    user.is_active = True
    user.save(update_fields=['is_active'])
    _add_to_default_group(user)
    messages.success(request, f"User '{user.username}' has been approved.")
    return redirect('user_management')


@login_required(login_url='login')
@admin_required
@require_POST
def reject_user(request: HttpRequest, user_id: int) -> HttpResponse:
    """Reject a pending user registration."""
    user = get_object_or_404(User, pk=user_id, is_active=False)
    username = user.username
    user.delete()
    messages.success(request, f"User request '{username}' has been rejected.")
    return redirect('user_management')


@login_required(login_url='login')
def profile(request: HttpRequest) -> HttpResponse:
    """Display user profile."""
    
    return render(request, 'dashboard/auth/profile.html', {
        'user': request.user
    })


@login_required(login_url='login')
@require_POST
def change_password(request: HttpRequest) -> HttpResponse:
    """Handle password change."""
    
    from django.contrib.auth.models import User
    from django.contrib.auth.hashers import check_password
    
    user = request.user
    old_password = request.POST.get('old_password')
    new_password = request.POST.get('new_password')
    confirm_password = request.POST.get('confirm_password')
    
    # Validate old password
    if not check_password(old_password, user.password):
        messages.error(request, "Current password is incorrect.")
        return redirect('profile')
    
    # Validate new passwords match
    if new_password != confirm_password:
        messages.error(request, "New passwords do not match.")
        return redirect('profile')
    
    # Validate new password length
    if len(new_password) < 8:
        messages.error(request, "New password must be at least 8 characters long.")
        return redirect('profile')
    
    # Update password
    user.set_password(new_password)
    user.save()
    
    messages.success(request, "Password changed successfully.")
    return redirect('profile')
