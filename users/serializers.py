from rest_framework import serializers
from .models import User, UserProfile

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password', 'first_name', 
                 'last_name', 'phone', 'user_type')
    
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'