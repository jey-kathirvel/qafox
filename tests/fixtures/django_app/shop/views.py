from django.db import models
from rest_framework import serializers, viewsets
from rest_framework.permissions import IsAuthenticated


class Product(models.Model):
    title = models.CharField(max_length=120)
    contact_email = models.EmailField()
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)


class ProductSerializer(serializers.ModelSerializer):
    title = serializers.CharField(min_length=2, max_length=120)
    contact_email = serializers.EmailField()
    owner_id = serializers.IntegerField(min_value=1)

    class Meta:
        model = Product
        fields = ["title", "contact_email", "owner_id"]


class ProductViewSet(viewsets.ModelViewSet):
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "product_id"

    def list(self, request):
        return []

    def retrieve(self, request, product_id=None):
        return []

    def create(self, request):
        return []
