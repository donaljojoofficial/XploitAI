from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.dashboard_url = reverse('dashboard_index')
        self.profile_url = reverse('profile')
        self.config_url = reverse('configuration')
        self.user_management_url = reverse('user_management')

    def test_registration_and_login_flow(self):
        # Registration page opens
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)

        # Submit registration
        # register new user (should not log in yet)
        response = self.client.post(self.register_url, {
            'username': 'tester',
            'email': 'tester@example.com',
            'password': 'complexpassword',
            'password_confirm': 'complexpassword'
        }, follow=True)
        self.assertRedirects(response, self.login_url)
        user = User.objects.get(username='tester')
        self.assertFalse(user.is_active)

        # pending user cannot log in before admin approval
        response = self.client.post(self.login_url, {
            'username': 'tester',
            'password': 'complexpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "pending administrator approval")

        # admin approves the request
        admin = User.objects.create_superuser('admin', 'admin@example.com', 'adminpass123')
        self.client.login(username='admin', password='adminpass123')
        resp = self.client.post(reverse('approve_user', kwargs={'user_id': user.id}), follow=True)
        self.assertRedirects(resp, self.user_management_url)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.client.post(self.logout_url, follow=True)

        # now try login flow
        response = self.client.post(self.login_url, {
            'username': 'tester',
            'password': 'complexpassword'
        }, follow=True)
        self.assertRedirects(response, self.dashboard_url)

        # test forgot-password request form appears
        response = self.client.get(reverse('password_reset'))
        self.assertEqual(response.status_code, 200)

        # test reset post
        response = self.client.post(reverse('password_reset'), {'email': 'tester@example.com'}, follow=True)
        self.assertRedirects(response, self.login_url)
        self.assertContains(response, "If an account with that email exists")

        # Check cache for code
        from django.core.cache import cache
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        user = User.objects.get(email='tester@example.com')
        code = cache.get(f"reset_code_{user.pk}")
        self.assertIsNotNone(code)

        # simulate verify view by constructing the URL from the email
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verify_url = reverse('password_reset_verify', kwargs={'uidb64': uid})
        resp2 = self.client.get(verify_url)
        self.assertEqual(resp2.status_code, 200)
        
        # post new password
        resp3 = self.client.post(verify_url, {'code': code, 'new_password': 'newpass123', 'confirm_password': 'newpass123'}, follow=True)
        self.assertRedirects(resp3, self.login_url)
        self.assertContains(resp3, "Password has been reset successfully")

        # logout again
        self.client.post(self.logout_url, follow=True)


    def test_access_control(self):
        # Unauthenticated should be redirected when accessing protected routes
        for url in [self.dashboard_url, self.profile_url, self.config_url, self.user_management_url]:
            response = self.client.get(url, follow=True)
            self.assertRedirects(response, f"{self.login_url}?next={url}")

        # Create user and login (non-admin)
        u = User.objects.create_user('alice', 'alice@example.com', 'password123')
        self.client.login(username='alice', password='password123')

        # dashboard & profile accessible, configuration restricted by admin_required decorator
        response = self.client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(self.config_url, follow=True)
        self.assertRedirects(response, f"{self.login_url}?next={self.config_url}")
        response = self.client.get(self.user_management_url, follow=True)
        self.assertRedirects(response, f"{self.login_url}?next={self.user_management_url}")

        # grant admin group and try again
        from django.contrib.auth.models import Group
        admin_group, _ = Group.objects.get_or_create(name='Admin')
        u.groups.add(admin_group)
        response = self.client.get(self.config_url)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(self.user_management_url)
        self.assertEqual(response.status_code, 200)
