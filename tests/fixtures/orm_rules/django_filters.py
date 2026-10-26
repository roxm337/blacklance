from django.db import models


class Item(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)
    private_note = models.TextField()
    password_hash = models.CharField(max_length=128)


class ItemFilter(FilterSet):
    filterset_fields = ["owner", "name"]
    search_fields = ["name", "private_note"]
    ordering_fields = ["name", "created_at"]

    def get_queryset(self):
        return Item.objects.filter(owner=self.request.user)
