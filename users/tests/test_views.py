import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from datetime import timedelta
from unittest.mock import patch
from django.core import mail
from django.utils.timezone import now
from users.tokens import email_verification_token_generator
from users.models import User, UserProfile 

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def user_data():
    return {
        "email": "test@example.com",
        "password": "Test@1234",
        "first_name": "John",
        "last_name": "Doe",
        "phone": "+1234567890",
        "date_of_birth": "1990-01-01",
        "profile": {
            "cpf": "123.456.789-00",
            "address": "Rua Teste, 123",
            "emergency_contact": "Jane Doe",
            "medical_conditions": "Nenhuma",
        },
    }

@pytest.fixture
def authenticated_user(db):
    # Criar o usuário
    user = User.objects.create_user(
        email="user@example.com",
        password="Test@1234",
        first_name="User",
        last_name="Test",
        is_active=True,
        email_verified=True
    )
    
    # Criar o perfil manualmente
    UserProfile.objects.create(
        user=user,
        cpf="123.456.789-00",
        address="Rua Teste, 123",
        emergency_contact="Jane Doe",
        medical_conditions="Nenhuma"
    )
    
    return user

@pytest.fixture
def auth_client(authenticated_user):
    client = APIClient()
    refresh = RefreshToken.for_user(authenticated_user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client

@pytest.mark.django_db
class TestAuthViewSet:
    def test_user_registration_success(self, api_client, user_data):
        url = reverse("auth-register")
        with patch('users.views.send_verification_email') as mock_send_email:
            response = api_client.post(url, data=user_data, format="json")
            
        assert response.status_code == 201
        assert User.objects.filter(email=user_data["email"]).exists()
        mock_send_email.assert_called_once()
        
        user = User.objects.get(email=user_data["email"])
        assert not user.is_active
        assert not user.email_verified
        assert user.profile.cpf == user_data["profile"]["cpf"]

    def test_user_registration_duplicate_email(self, api_client, user_data):
        User.objects.create_user(email=user_data["email"], password="Test@1234")
        url = reverse("auth-register")
        response = api_client.post(url, data=user_data, format="json")
        assert response.status_code == 400
        assert "email" in response.data

    def test_login_success(self, api_client):
        user = User.objects.create_user(
            email="login@example.com",
            password="Test@1234",
            is_active=True,
            email_verified=True
        )
        
        url = reverse("auth-login")
        data = {"email": "login@example.com", "password": "Test@1234"}
        response = api_client.post(url, data=data)
        
        assert response.status_code == 200
        assert "access" in response.data
        assert "refresh" in response.data

    def test_login_inactive_account(self, api_client):
        User.objects.create_user(
            email="inactive@example.com",
            password="Test@1234",
            is_active=False
        )
        
        url = reverse("auth-login")
        data = {"email": "inactive@example.com", "password": "Test@1234"}
        response = api_client.post(url, data=data)
        
        assert response.status_code == 401
        assert "Sua conta está desativada" in response.data["error"]

    def test_logout_success(self, auth_client, authenticated_user):
        url = reverse("auth-logout")
        refresh = RefreshToken.for_user(authenticated_user)  # Use o usuário autenticado diretamente
        response = auth_client.post(url, {"refresh": str(refresh)})
        assert response.status_code == 200
        assert "Logout realizado com sucesso" in response.data["message"]

    def test_email_verification_success(self, api_client):
        user = User.objects.create_user(
            email="verify@example.com",
            password="Test@1234",
            email_verified=False,
            is_active=False
        )
        # Gera um token válido para o usuário
        token = email_verification_token_generator.make_token(user)
        user.email_verification_token = token
        user.email_verification_token_created = now()
        user.save()

        url = reverse("auth-verify-email") + f"?token={token}&email={user.email}"
        response = api_client.get(url)

        assert response.status_code == 200
        user.refresh_from_db()
        assert user.email_verified
        assert user.is_active

    def test_resend_verification_email(self, api_client):
        user = User.objects.create_user(
            email="resend@example.com",
            password="Test@1234",
            email_verified=False
        )
        
        url = reverse("auth-resend-verification")
        with patch('users.views.send_verification_email') as mock_send_email:
            response = api_client.post(url, {"email": user.email})
            
        assert response.status_code == 200
        mock_send_email.assert_called_once()
        assert "Novo email de verificação enviado" in response.data["message"]

@pytest.mark.django_db
class TestUserViewSet:
    def test_update_profile(self, auth_client, authenticated_user):
        # Garantir que o perfil existe para o usuário autenticado
        assert hasattr(authenticated_user, 'profile'), "O usuário não possui um perfil associado."

        # URL para atualização do perfil
        url = reverse("users-update-profile")

        # Dados para atualização do perfil
        data = {
            "first_name": "NewName",
            "profile": {
                "cpf": "987.654.321-00",
                "address": "Nova Rua, 456"
            }
        }

        # Fazer a requisição PATCH para atualizar o perfil
        response = auth_client.patch(url, data=data, format="json")

        # Verificar se a resposta foi bem-sucedida
        assert response.status_code == 200, f"Erro na resposta: {response.data}"

        # Atualizar o objeto do usuário autenticado do banco de dados
        authenticated_user.refresh_from_db()

        # Verificar se o primeiro nome foi atualizado
        assert authenticated_user.first_name == "NewName", "O primeiro nome não foi atualizado corretamente."

        # Verificar se os campos do perfil foram atualizados
        assert authenticated_user.profile.cpf == "987.654.321-00", "O CPF do perfil não foi atualizado corretamente."
        assert authenticated_user.profile.address == "Nova Rua, 456", "O endereço do perfil não foi atualizado corretamente."

    def test_update_password(self, auth_client, authenticated_user):
        url = reverse("users-update-profile")
        data = {
            "current_password": "Test@1234",
            "new_password": "NewPass@1234"
        }
        response = auth_client.patch(url, data=data, format="json")
        
        assert response.status_code == 200
        authenticated_user.refresh_from_db()
        assert authenticated_user.check_password("NewPass@1234")