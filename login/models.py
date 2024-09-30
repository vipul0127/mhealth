from django.db import models

class ExcelFile(models.Model):
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='files/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


from django.db import models
from django.contrib.auth.models import User
import random

class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_otp(self):
        otp = str(random.randint(100000, 999999))
        self.otp_code = otp
        self.save()
        return otp


from django.db import models

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} at {self.timestamp}"



# models.py

from django.db import models

from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User

from django.db import models
from django.contrib.auth.models import User

class ParticipantConsent(models.Model):
    # Link to the User model
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="consent")

    # Health-related information
    age = models.IntegerField(default=30)  # Default age
    gender = models.CharField(max_length=10, default='Unknown')  # Default gender
    height = models.FloatField(default=170.0)  # Default height in cm
    weight = models.FloatField(default=70.0)  # Default weight in kg

    respiratory_conditions = models.CharField(max_length=255, blank=True, null=True, default='None')
    cardiovascular_conditions = models.CharField(max_length=255, blank=True, null=True, default='None')
    cardiovascular_symptoms = models.CharField(max_length=255, blank=True, null=True, default='None')
    metabolic_conditions = models.CharField(max_length=255, blank=True, null=True, default='None')
    mental_health_conditions = models.CharField(max_length=255, blank=True, null=True, default='None')
    stress_level = models.CharField(max_length=50, default='Low')  # Default stress level

    lifestyle_factors = models.CharField(max_length=255, blank=True, null=True, default='Sedentary')  # Default lifestyle
    sleep_hours = models.CharField(max_length=50, default='7-8 hours')  # Default sleep hours
    sleep_disorders = models.CharField(max_length=255, blank=True, null=True, default='None')

    last_medical_checkup = models.CharField(max_length=50, default='Within the last year')  # Default checkup
    health_concerns = models.CharField(max_length=255, blank=True, null=True, default='None')

    # Date of submission
    date_submitted = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Consent of {self.user.username} - {self.user.email}"
