from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import ExcelFile
from django.http import HttpResponseForbidden

class ExcelFileAdmin(admin.ModelAdmin):
    list_display = ('name', 'uploaded_at')
    fields = ['name', 'file']

    # Override save_model to restrict uploads to superusers
    def save_model(self, request, obj, form, change):
        if request.user.is_superuser:
            super().save_model(request, obj, form, change)
        else:
            return HttpResponseForbidden("You are not allowed to upload files.")

    # Disable delete permission for non-superusers (optional)
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser

admin.site.register(ExcelFile, ExcelFileAdmin)
from .models import ParticipantConsent
admin.site.register(ParticipantConsent)


from django.contrib import admin
from .models import ContactMessage

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'timestamp')  # Customize as needed
    search_fields = ('name', 'email', 'message')  # Optional: adds search functionality
    list_filter = ('timestamp',)  # Optional: adds filter functionality
