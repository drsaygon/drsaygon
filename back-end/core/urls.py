from django.contrib import admin
from django.urls import path, include
from .views import teste_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),
    path('teste/', teste_view, name='teste'),    
]