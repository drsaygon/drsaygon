from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User, UserProfile
from django.utils.translation import gettext_lazy as _

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('cpf', 'address', 'emergency_contact', 'medical_conditions', 'profile_picture')

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = (
            'id', 'email', 'password', 'first_name', 'last_name',
            'phone', 'user_type', 'profile', 'date_of_birth'
        )
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True}
        }

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(_("Este email já está em uso."))
        return value

    def create(self, validated_data):
        profile_data = validated_data.pop('profile', None)
        password = validated_data.pop('password')
        
        user = User(**validated_data)
        user.set_password(password)
        user.save()

        if profile_data:
            UserProfile.objects.create(user=user, **profile_data)
        else:
            UserProfile.objects.create(user=user)

        return user

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if password:
            instance.set_password(password)
        
        instance.save()

        if profile_data and hasattr(instance, 'profile'):
            for attr, value in profile_data.items():
                setattr(instance.profile, attr, value)
            instance.profile.save()

        return instance

class UserUpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('cpf', 'address', 'emergency_contact', 'medical_conditions')
        
    def validate_cpf(self, value):
        if value and UserProfile.objects.exclude(user=self.context['request'].user).filter(cpf=value).exists():
            raise serializers.ValidationError(_("Este CPF já está em uso."))
        return value

class UserUpdateSerializer(serializers.ModelSerializer):
    profile = UserUpdateProfileSerializer(required=False)
    current_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'phone',
            'date_of_birth', 'profile',
            'current_password', 'new_password'
        )
        
    def validate(self, attrs):
        current_password = attrs.pop('current_password', None)
        new_password = attrs.pop('new_password', None)
        
        if bool(current_password) != bool(new_password):
            raise serializers.ValidationError({
                'password': _("Ambos os campos de senha atual e nova senha são necessários para alterar a senha")
            })
            
        if current_password:
            user = self.context['request'].user
            if not user.check_password(current_password):
                raise serializers.ValidationError({
                    'current_password': _("Senha atual incorreta")
                })
                
            try:
                validate_password(new_password, user)
            except Exception as e:
                raise serializers.ValidationError({
                    'new_password': list(e)
                })
                
            attrs['new_password'] = new_password
            
        return attrs

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', None)
        new_password = validated_data.pop('new_password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            
        if new_password:
            instance.set_password(new_password)
            
        instance.save()
        
        if profile_data and hasattr(instance, 'profile'):
            for attr, value in profile_data.items():
                setattr(instance.profile, attr, value)
            instance.profile.save()
            
        return instance