from rest_framework import viewsets, status
from rest_framework.decorators import action, permission_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .serializers import UserSerializer, UserUpdateSerializer
from .models import User

from .utils import send_verification_email, is_verification_token_expired
from .tokens import email_verification_token_generator
from django.shortcuts import get_object_or_404

import logging

logger = logging.getLogger(__name__)

class AuthViewSet(viewsets.ViewSet):
    serializer_class = UserSerializer

    @action(detail=False, methods=['post'])
    @permission_classes([AllowAny])
    def register(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': self.serializer_class(user).data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error during registration: {e}")
                return Response({
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @permission_classes([AllowAny])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({
                'error': _('Por favor, forneça email e senha.')
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({
                'error': _('Email inválido.')
            }, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)
        
        if user:
            if not user.is_active:
                return Response({
                    'error': _('Sua conta está desativada.')
                }, status=status.HTTP_401_UNAUTHORIZED)
                
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': self.serializer_class(user).data
            })
        return Response({
            'error': _('Credenciais inválidas')
        }, status=status.HTTP_401_UNAUTHORIZED)

    @action(detail=False, methods=['post'])
    @authentication_classes([JWTAuthentication])
    @permission_classes([IsAuthenticated])
    def logout(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"error": _("Refresh token é necessário")},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(
                {"message": _("Logout realizado com sucesso")},
                status=status.HTTP_200_OK
            )
        except TokenError:
            return Response(
                {"error": _("Token inválido ou expirado")},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        
    @action(detail=False, methods=['post'])
    @permission_classes([AllowAny])
    def register(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                
                # Enviar email de verificação
                domain = request.META.get('HTTP_ORIGIN', 'http://localhost:3000')
                send_verification_email(user, domain)
                
                return Response({
                    'message': _('Registro realizado com sucesso. Por favor, verifique seu email para ativar sua conta.'),
                    'user': self.serializer_class(user).data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error during registration: {e}")
                return Response({
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    @permission_classes([AllowAny])
    def verify_email(self, request):
        token = request.query_params.get('token')
        email = request.query_params.get('email')
        
        if not token or not email:
            return Response({
                'error': _('Parâmetros inválidos.')
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = get_object_or_404(User, email=email)
            
            if user.email_verified:
                return Response({
                    'message': _('Email já verificado.')
                }, status=status.HTTP_200_OK)
                
            if user.email_verification_token != token:
                return Response({
                    'error': _('Token inválido.')
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if is_verification_token_expired(user.email_verification_token_created):
                return Response({
                    'error': _('Token expirado. Solicite um novo email de verificação.')
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if not email_verification_token_generator.check_token(user, token):
                return Response({
                    'error': _('Token inválido.')
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user.email_verified = True
            user.is_active = True
            user.email_verification_token = None
            user.email_verification_token_created = None
            user.save()
            
            return Response({
                'message': _('Email verificado com sucesso. Você já pode fazer login.')
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error during email verification: {e}")
            return Response({
                'error': _('Erro ao verificar email.')
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    @permission_classes([AllowAny])
    def resend_verification(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({
                'error': _('Email é obrigatório.')
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = get_object_or_404(User, email=email)
            
            if user.email_verified:
                return Response({
                    'message': _('Email já verificado.')
                }, status=status.HTTP_200_OK)
            
            domain = request.META.get('HTTP_ORIGIN', 'http://localhost:3000')
            send_verification_email(user, domain)
            
            return Response({
                'message': _('Novo email de verificação enviado.')
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error resending verification email: {e}")
            return Response({
                'error': _('Erro ao reenviar email de verificação.')
            }, status=status.HTTP_400_BAD_REQUEST)        

class UserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @action(detail=False, methods=['put', 'patch'])
    def update_profile(self, request):
        try:
            user = request.user
            partial = request.method == 'PATCH'
            
            # Handle password update
            if 'current_password' in request.data and 'new_password' in request.data:
                if not user.check_password(request.data['current_password']):
                    return Response(
                        {'error': _('Senha atual incorreta')},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                user.set_password(request.data['new_password'])
                user.save()
                return Response({'message': _('Senha atualizada com sucesso')})

            serializer = UserUpdateSerializer(
                user,
                data=request.data,
                partial=partial,
                context={'request': request}
            )

            if serializer.is_valid():
                serializer.save()
                return Response({
                    'message': _('Perfil atualizado com sucesso'),
                    'user': serializer.data
                }, status=status.HTTP_200_OK)
            
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            return Response({
                'error': _('Erro ao atualizar o perfil')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)