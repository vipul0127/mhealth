from django import forms
from .models import ExcelFile
from django import forms
from django.contrib.auth.models import User
from django.core.validators import EmailValidator

from django import forms
from django.core.exceptions import ValidationError
from .models import User  # Assuming you're using a custom User model

class ExcelFileForm(forms.ModelForm):
    class Meta:
        model = ExcelFile
        fields = ['name', 'file']

class ContactForm(forms.Form):
    name = forms.CharField(max_length=100)
    email = forms.EmailField()
    message = forms.CharField(widget=forms.Textarea)

class UploadFileForm(forms.ModelForm):
    file_name = forms.CharField(max_length=100, required=True, label='File Name')
    file = forms.FileField()

    class Meta:
        model = ExcelFile
        fields = ['file_name', 'file']

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file extension
            if not (file.name.endswith('.csv') or file.name.endswith('.xls') or file.name.endswith('.xlsx')):
                raise forms.ValidationError("File format not supported. Please upload a CSV or Excel file.")
            return file
        raise forms.ValidationError("No file uploaded.")



class SignupForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput(), label="Password")
    password2 = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")

    # Additional health-related fields
    age = forms.IntegerField(label="Age", required=True)
    gender_choices = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    gender = forms.ChoiceField(choices=gender_choices, required=True)

    height = forms.FloatField(label="Height (in cm)", required=True)
    weight = forms.FloatField(label="Weight (in kg)", required=True)

    # Cardiovascular health
    cardiovascular_conditions_choices = [
        ('Hypertension', 'Hypertension (High Blood Pressure)'),
        ('Hypotension', 'Hypotension (Low Blood Pressure)'),
        ('Arrhythmia', 'Arrhythmia (Irregular Heartbeat)'),
        ('None', 'No cardiovascular conditions'),
        ('Other', 'Other'),
    ]
    cardiovascular_conditions = forms.MultipleChoiceField(
        choices=cardiovascular_conditions_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    cardiovascular_other = forms.CharField(max_length=100, required=False, label="Other cardiovascular conditions")

    cardiovascular_symptoms_choices = [
        ('Chest Pain', 'Chest Pain'),
        ('Shortness of Breath', 'Shortness of Breath'),
        ('Palpitations', 'Palpitations'),
        ('Dizziness', 'Dizziness'),
        ('None', 'No symptoms'),
        ('Other', 'Other'),
    ]
    cardiovascular_symptoms = forms.MultipleChoiceField(
        choices=cardiovascular_symptoms_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    cardiovascular_symptoms_other = forms.CharField(max_length=100, required=False, label="Other cardiovascular symptoms")

    # Metabolic health
    metabolic_conditions_choices = [
        ('Type 1 Diabetes', 'Type 1 Diabetes'),
        ('Type 2 Diabetes', 'Type 2 Diabetes'),
        ('Prediabetes', 'Prediabetes'),
        ('None', 'No metabolic conditions'),
        ('Other', 'Other'),
    ]
    metabolic_conditions = forms.MultipleChoiceField(
        choices=metabolic_conditions_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    metabolic_other = forms.CharField(max_length=100, required=False, label="Other metabolic conditions")

    # Mental and emotional health
    mental_health_conditions_choices = [
        ('Anxiety', 'Anxiety Disorder'),
        ('Depression', 'Depression'),
        ('Panic', 'Panic Disorder'),
        ('None', 'No mental health conditions'),
        ('Other', 'Other'),
    ]
    mental_health_conditions = forms.MultipleChoiceField(
        choices=mental_health_conditions_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    mental_health_other = forms.CharField(max_length=100, required=False, label="Other mental health conditions")

    stress_level_choices = [
        ('Never', 'Never'),
        ('Rarely', 'Rarely'),
        ('Occasionally', 'Occasionally'),
        ('Frequently', 'Frequently'),
        ('Always', 'Always'),
    ]
    stress_level = forms.ChoiceField(choices=stress_level_choices, required=True, label="How often do you experience high levels of stress?")

    # Lifestyle factors
    lifestyle_factors_choices = [
        ('Smoker', 'Current or past smoker'),
        ('Alcohol', 'Regular alcohol consumption'),
        ('Sedentary', 'Sedentary lifestyle (little to no physical activity)'),
        ('Active', 'Regular physical activity (at least 3 times per week)'),
        ('None', 'No significant lifestyle factors'),
        ('Other', 'Other'),
    ]
    lifestyle_factors = forms.MultipleChoiceField(
        choices=lifestyle_factors_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    lifestyle_other = forms.CharField(max_length=100, required=False, label="Other lifestyle factors")

    # Sleep patterns
    sleep_hours_choices = [
        ('Less than 5 hours', 'Less than 5 hours'),
        ('5-6 hours', '5-6 hours'),
        ('7-9 hours', '7-9 hours'),
        ('More than 10 hours', 'More than 10 hours'),
    ]
    sleep_hours = forms.ChoiceField(choices=sleep_hours_choices, required=True, label="How many hours of sleep do you typically get per night?")

    sleep_disorders_choices = [
        ('Insomnia', 'Insomnia'),
        ('Sleep Apnea', 'Sleep Apnea'),
        ('None', 'No sleep disorders'),
        ('Other', 'Other'),
    ]
    sleep_disorders = forms.MultipleChoiceField(
        choices=sleep_disorders_choices, widget=forms.CheckboxSelectMultiple(), required=False
    )
    sleep_disorders_other = forms.CharField(max_length=100, required=False, label="Other sleep disorders")

    # Recent medical history
    last_medical_checkup_choices = [
        ('Within the last year', 'Within the last year'),
        ('1-2 years ago', '1-2 years ago'),
        ('More than 2 years ago', 'More than 2 years ago'),
    ]
    last_medical_checkup = forms.ChoiceField(choices=last_medical_checkup_choices, required=True, label="When was your last full medical check-up?")
    health_concerns = forms.CharField(max_length=100, required=False, label="Health concerns identified during the last check-up")

    class Meta:
        model = User  # Use your custom User model here
        fields = ['username', 'email', 'password1', 'password2', 'age', 'gender', 'height', 'weight']

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords do not match.")
        
        return cleaned_data





from django import forms
from .models import ParticipantConsent

class ConsentForm(forms.ModelForm):
    class Meta:
        model = ParticipantConsent
        fields = [
            'age', 'gender', 'height', 'weight',
            'respiratory_conditions', 'cardiovascular_conditions',
            'cardiovascular_symptoms', 'metabolic_conditions',
            'mental_health_conditions', 'stress_level', 'lifestyle_factors',
            'sleep_hours', 'sleep_disorders', 'last_medical_checkup', 'health_concerns'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Optionally, set initial values for fields to reflect defaults
        self.fields['age'].initial = 30
        self.fields['gender'].initial = 'Unknown'
        self.fields['height'].initial = 170.0
        self.fields['weight'].initial = 70.0
        self.fields['stress_level'].initial = 'Low'
        self.fields['lifestyle_factors'].initial = 'Sedentary'
        self.fields['sleep_hours'].initial = '7-8 hours'
        self.fields['last_medical_checkup'].initial = 'Within the last year'
