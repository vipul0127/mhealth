
from django.contrib.auth.models import User
from django.core.validators import EmailValidator, ValidationError
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate,login,logout
from django.http import HttpResponse
import csv
from django.http import HttpResponse
import io
import requests
from .models import ExcelFile
from django.http import HttpResponse

# views.py

from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView
)
from django.urls import reverse_lazy

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset_form.html'
    email_template_name = 'password_reset_email.html'
    success_url = reverse_lazy('password_reset_done')

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'password_reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password_reset_complete.html'

def test_session(request):
    if 'visited' in request.session:
        request.session['visited'] += 1
    else:
        request.session['visited'] = 1
    return HttpResponse(f"Number of visits: {request.session['visited']}")

def generate_hl7(request):
    # URL of the file in the GitHub repository
    file_url = 'https://raw.githubusercontent.com/sakethwithanh/mHealth-frontend/main/AHLSAM018434.csv'

    try:
        # Download the file and save it as a string
        csv_file_content = requests.get(file_url).text

        # Read data from CSV content directly
        csv_reader = csv.DictReader(csv_file_content.splitlines())
        dataset = list(csv_reader)

        # Create an HL7 message template (MSH segment)
        hl7_message = (
            "MSH|^~\\&|YourApp|YourFacility|HL7Server|HL7Server|20230908170000||ORU^R01|123456|P|2.5|||\n"
        )

        # Iterate through the dataset and create an HL7 message for each record
        for record in dataset:
            # Create a new HL7 message for each record
            hl7_message += f"PID|1||{record['Time']}||{record['Sleep']}|||\n"

            # OBX segment for GSR
            obx_gsr = (
                f"OBX|1|NM|GSR^Galvanic Skin Response^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['GSR']}\n"
            )
            hl7_message += obx_gsr

            # OBX segment for CBT
            obx_cbt = (
                f"OBX|2|NM|CBT^Core Body Temperature^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['CBT(degC)']}\n"
            )
            hl7_message += obx_cbt

            # OBX segment for PPG
            obx_ppg = (
                f"OBX|3|NM|PPG^Photoplethysmogram^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['PPG']}\n"
            )
            hl7_message += obx_ppg

            # OBX segment for ECG
            obx_ecg = (
                f"OBX|4|NM|ECG^Electrocardiogram^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['ECG']}\n"
            )
            hl7_message += obx_ecg

        # Set the proper content type for plain text
        response = HttpResponse(hl7_message, content_type='text/plain')
        
        # Set the Content-Disposition header to inline
        response['Content-Disposition'] = 'inline; filename="hl7_messages.hl7"'
        
        return response

    except requests.exceptions.RequestException as e:
        # Handle the exception (print/log the error, return an appropriate response, etc.)
        print(f"Error fetching data from GitHub: {e}")
        return HttpResponse("Internal Server Error", status=500)

def download_hl7(request):
    # URL of the file in the GitHub repository
    file_url = 'https://raw.githubusercontent.com/sakethwithanh/mHealth-frontend/main/AHLSAM018434.csv'

    try:
        # Download the file and save it as a string
        csv_file_content = requests.get(file_url).text

        # Read data from CSV content directly
        csv_reader = csv.DictReader(csv_file_content.splitlines())
        dataset = list(csv_reader)

        # Create an HL7 message template (MSH segment)
        hl7_message = (
            "MSH|^~\\&|YourApp|YourFacility|HL7Server|HL7Server|20230908170000||ORU^R01|123456|P|2.5|||\n"
        )

        # Iterate through the dataset and create an HL7 message for each record
        for record in dataset:
            # Create a new HL7 message for each record
            hl7_message += f"PID|1||{record['Time']}||{record['Sleep']}|||\n"

            # OBX segment for GSR
            obx_gsr = (
                f"OBX|1|NM|GSR^Galvanic Skin Response^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['GSR']}\n"
            )
            hl7_message += obx_gsr

            # OBX segment for CBT
            obx_cbt = (
                f"OBX|2|NM|CBT^Core Body Temperature^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['CBT(degC)']}\n"
            )
            hl7_message += obx_cbt

            # OBX segment for PPG
            obx_ppg = (
                f"OBX|3|NM|PPG^Photoplethysmogram^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['PPG']}\n"
            )
            hl7_message += obx_ppg

            # OBX segment for ECG
            obx_ecg = (
                f"OBX|4|NM|ECG^Electrocardiogram^HL7|||{record['Time']}|||||AmplitudeData^{record['Time']}^Units|{record['ECG']}\n"
            )
            hl7_message += obx_ecg

        # Set the proper content type for plain text
        response = HttpResponse(hl7_message, content_type='text/plain')
        
        # Set the Content-Disposition header to trigger download
        response['Content-Disposition'] = 'attachment; filename="hl7_messages.hl7"'
        
        return response

    except requests.exceptions.RequestException as e:
        # Handle the exception (print/log the error, return an appropriate response, etc.)
        print(f"Error fetching data from GitHub: {e}")
        return HttpResponse("Internal Server Error", status=500)


def HomePage(request):
    return render(request,'home.html')


from django.shortcuts import render, redirect
from .forms import ExcelFileForm

from django.shortcuts import render, redirect


from django.shortcuts import render, redirect
from .forms import ExcelFileForm

def upload_success(request):
    return render(request, 'upload_success.html')
from django.shortcuts import render
from .models import ExcelFile

# views.py
from django.shortcuts import render, get_object_or_404
from .models import ExcelFile

def SheetPage(request, id):
    file = get_object_or_404(ExcelFile, id=id)
    # Pass the file to the template or perform other logic
    return render(request, 'sheet.html', {'file': file})

from django.shortcuts import render
from .models import ExcelFile

import pandas as pd
from django.shortcuts import render
from .models import ExcelFile
from .forms import UploadFileForm

from django.shortcuts import render
from .models import ExcelFile

def home_view(request):
    # Retrieve all ExcelFile objects
    excel_files = ExcelFile.objects.all()

    # Pass the data to the template
    context = {
        'excel_files': excel_files,
    }
    return render(request, 'home.html', context)

# views.py
from django.shortcuts import render, redirect
from .forms import UploadFileForm
from .models import ExcelFile

def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file_name = form.cleaned_data['file_name']
            file = request.FILES['file']
            
            try:
                excel_file = ExcelFile(name=file_name, file=file)
                excel_file.save()
                print(f"File saved: {excel_file.name}")
                return redirect('upload_success')
            except Exception as e:
                print(f"Error saving file: {e}")
                # Handle error or display message to user
        else:
            print(f"Form errors: {form.errors}")
            return render(request, 'upload.html', {'form': form})
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})



from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse
import random
import json
import random
import json
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.validators import EmailValidator
from django.http import JsonResponse

from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import OTP
from django.contrib import messages
from django.contrib import messages
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from .models import User, OTP

from django.contrib import messages
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import User, OTP



from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
from .forms import SignupForm, ConsentForm

def signup(request):
    if request.method == 'POST':
        signup_form = SignupForm(request.POST)
        consent_form = ConsentForm(request.POST)
        
        if signup_form.is_valid() and consent_form.is_valid():
            # Create the user
            user = signup_form.save(commit=False)
            user.set_password(signup_form.cleaned_data['password1'])
            user.save()
            
            # Create the consent instance
            consent = consent_form.save(commit=False)
            consent.user = user  # Set the user as the foreign key
            consent.save()
            
            # Log the user in
            login(request, user)
            return redirect('some_success_url')  # Replace with your success URL
            
    else:
        signup_form = SignupForm()
        consent_form = ConsentForm()
        
    return render(request, 'signup.html', {
        'signup_form': signup_form,
        'consent_form': consent_form,
    })


def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        if otp == str(request.session.get('otp')):
            username = request.POST.get('username')
            email = request.POST.get('email')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')

            if password1 != password2:
                return JsonResponse({'success': False, 'message': 'Passwords do not match'})

            # Check if the username or email already exists
            if User.objects.filter(username=username).exists():
                return JsonResponse({'success': False, 'message': 'Username is already taken'})
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'success': False, 'message': 'Email is already registered'})

            try:
                # Create user
                User.objects.create_user(username=username, email=email, password=password1)
                return JsonResponse({'success': True, 'message': 'Signup successful'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Error creating user: {str(e)}'})
        else:
            return JsonResponse({'success': False, 'message': 'Invalid OTP. Please retry.'})

    return JsonResponse({'success': False, 'message': 'Invalid request method'})
from django.http import JsonResponse
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
import random
import json

def send_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            username = data.get('username')

            # Validate email format
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'success': False, 'message': 'Invalid email address'})

            # Check if the email or username is already registered
            if User.objects.filter(email=email).exists():
                return JsonResponse({'success': False, 'message': 'Email is already registered'})

            if User.objects.filter(username=username).exists():
                return JsonResponse({'success': False, 'message': 'Username is already taken'})

            # Generate and save OTP
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['email'] = email
            request.session['username'] = username

            # Send OTP via email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'vipulkhosya00007@gmail.com',  # Replace with your sending email
                [email],
                fail_silently=False,
            )

            return JsonResponse({'success': True, 'message': 'OTP sent successfully'})

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': 'Invalid request format'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'An error occurred: {str(e)}'})

    return JsonResponse({'success': False, 'message': 'Invalid request method'})

def LoginPage(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to home if login is successful
        else:
            messages.error(request, 'Invalid username or password')  # Show error message on invalid login
    
    return render(request, 'login.html')  # Render the login template

def LogoutPage(request):
    logout(request)
    return redirect('welcome')



def SheetPage(request):
    return render(request, 'sheets.html')

# views.py

def download_csv_data(request):
    # Replace this with your logic to fetch data from the Google Sheet
    # For example, you can use gspread library or any other method to get the data
    sheet_data = [
        ["Header1", "Header2", "Header3"],
        ["Data1", "Data2", "Data3"],
        # Add more rows as needed
    ]

    # Create a CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="google_sheet_data.csv"'

    # Create a CSV writer and write the data to the response
    csv_writer = csv.writer(response)
    for row in sheet_data:
        csv_writer.writerow(row)

    return response



from django.shortcuts import render, get_object_or_404
from .models import ExcelFile

def file_detail(request, file_id):
    file = get_object_or_404(ExcelFile, id=file_id)
    return render(request, 'file_detail.html', {'file': file})








import pandas as pd
from django.shortcuts import render, get_object_or_404
from .models import ExcelFile
import pandas as pd
from django.shortcuts import render, get_object_or_404
from .models import ExcelFile

import pandas as pd
from django.shortcuts import render
from .models import ExcelFile

def view_ppg(request, file_id):
    
        # Retrieve the ExcelFile object
    excel_file = ExcelFile.objects.get(id=file_id)
        
        # Read the CSV file
    df = pd.read_csv(excel_file.file.path)
        
        # Convert the DataFrame to a dictionary for easier use in the template
    data = df.to_dict(orient='records')
        
        # Pass the data to the template
    context = {
        'data': data,
    }
    return render(request, 'view_ppg.html', context)
        
   




import matplotlib.pyplot as plt
from django.http import HttpResponse
import pandas as pd
from .models import ExcelFile

import pandas as pd
import matplotlib.pyplot as plt
import io
from django.http import HttpResponse
from .models import ExcelFile
from django.shortcuts import get_object_or_404
# views.py

import gspread
from oauth2client.service_account import ServiceAccountCredentials
from django.shortcuts import render
import pandas as pd
import plotly.express as px
from django.http import JsonResponse

def access_excel(request):
    # Google Sheets API setup
    scope = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
    creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)  # Update with your credentials file path
    client = gspread.authorize(creds)

    # Access the Google Sheet
    sheet = client.open_by_key('2PACX-1vRaQsqTs4elSrtWoSdwsfSTUm_-zF2kWFtmoFGtvEK5ftqnRxKgbRMB07TUyF3oKv7rwpOvdaDS1LDj')  # Replace with your Google Sheet ID
    worksheet = sheet.worksheet('graph')  # Update with the sheet name if different

    # Fetch data from specific columns
    data = worksheet.get_all_records()
    df = pd.DataFrame(data)

    # Ensure the columns exist
    if 'PPG' in df.columns and 'Time' in df.columns:
        # Create a Plotly line chart
        fig = px.line(df, x='Time', y='PPG', title='PPG vs Time')

        # Convert plot to JSON for frontend rendering
        graph_json = fig.to_json()

        return render(request, 'access_excel.html', {'graph_json': graph_json})
    else:
        return render(request, 'access_excel.html', {'error': 'Required columns PPG and Time not found in the sheet.'})

def generate_ppg_graph(request, file_id):
    # Retrieve the file object
    file = get_object_or_404(ExcelFile, pk=file_id)
    file_path = file.file.path  # Path to the uploaded CSV file

    # Read the CSV file into a DataFrame
    df = pd.read_csv(file_path)

    # Extract the 'PPG' and 'Time' columns
    ppg_data = df[['Time', 'PPG']].dropna()  # Drop rows with NaN values if necessary

    # Create the plot
    plt.figure(figsize=(10, 5))
    plt.plot(ppg_data['Time'], ppg_data['PPG'], label='PPG')
    plt.xlabel('Time')
    plt.ylabel('PPG')
    plt.title('PPG Data Over Time')
    plt.legend()
    plt.grid(True)

    # Save the plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()

    # Return the image as a response
    return HttpResponse(img, content_type='image/png')





import csv
from django.shortcuts import render
from django.http import HttpResponse
from .models import ExcelFile

import csv
import matplotlib.pyplot as plt
from django.shortcuts import render
from django.http import HttpResponse
from .models import ExcelFile
import io
import urllib, base64

from django.shortcuts import render, get_object_or_404
from .models import ExcelFile
from django.http import HttpResponse
import matplotlib.pyplot as plt
import io
import urllib, base64
import matplotlib
import csv
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator

matplotlib.use('Agg')  # Use a non-GUI backend for Matplotlib

def time_to_seconds(time_str):
    try:
        h, m, s = map(int, time_str.split(':'))
        return h * 3600 + m * 60 + s
    except ValueError:
        return None

import io
import base64
import csv
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from .models import ExcelFile  # Adjust according to your actual model import

import io
import base64
import csv
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from .models import ExcelFile  # Adjust according to your actual model import

import io
import base64
import csv
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from .models import ExcelFile  # Adjust according to your actual model import

import csv
import io
import base64
from django.shortcuts import render, get_object_or_404
from matplotlib import pyplot as plt
from matplotlib.ticker import MaxNLocator

def time_to_seconds(time_str):
    """Converts time strings to seconds. Expected format: 'HH:MM:SS'."""
    try:
        hours, minutes, seconds = map(int, time_str.split(':'))
        return hours * 3600 + minutes * 60 + seconds
    except ValueError:
        return None

def display_csv(request, file_id):
    # Fetch the ExcelFile object
    excel_file = get_object_or_404(ExcelFile, id=file_id)

    # Initialize lists for PPG values and time in seconds
    ppg = []
    time = []

    # Read the CSV file and extract data
    try:
        with open(excel_file.file.path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if 'PPG' in row and 'Time' in row:
                    time_seconds = time_to_seconds(row['Time'])
                    if time_seconds is not None:
                        try:
                            ppg_value = float(row['PPG'])
                            ppg.append(ppg_value)
                            time.append(time_seconds)
                        except ValueError:
                            pass  # Skip rows with invalid PPG values
    except Exception as e:
        return HttpResponse(f"Error reading the file: {e}", status=500)

    # Check if data lists are empty
    if not time or not ppg:
        return HttpResponse("No valid data found in the file.", status=400)

    # Create a full day x-axis (0 to 86400 seconds)
    full_day_x = list(range(0, 86401))  # Full day from 0 to 86400 seconds
    ppg_full_day = [0] * len(full_day_x)  # Initialize PPG values for the full day

    # Map available time data to the full day PPG data
    for t, p in zip(time, ppg):
        if 0 <= t <= 86400:
            ppg_full_day[t] = p  # Assign PPG value to the corresponding second

    # Create a plot
    fig, ax = plt.subplots()
    ax.scatter(time, ppg, color='blue', label='PPG Data', marker='o')  # Scatter plot for actual data points
    ax.plot(full_day_x, ppg_full_day, label='PPG vs Time', color='lightblue', alpha=0.5)  # Line to connect the points
    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('PPG')
    ax.set_title('PPG vs Time for a Full Day')
    ax.legend()

    # Set x-axis limits to cover the full day
    ax.set_xlim([0, 86400])  # Full day in seconds (0 to 86400)

    # Set time intervals at every hour
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x // 3600)}:00'))

    # Add grid lines and ticks at the intervals
    ax.grid(True, which='both', linestyle='--', linewidth=0.5)
    ax.set_xticks(range(0, 86401, 3600))  # Set ticks every hour

    # Save plot to a BytesIO object
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close(fig)
    buffer.seek(0)

    # Encode the image in base64
    image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # Prepare the context for rendering
    context = {
        'image_base64': image_base64,
        'file': excel_file
    }

    return render(request, 'display_csv.html', context)


import chardet

def get_encoding(file_path):
    """Detect the encoding of the file."""
    with open(file_path, 'rb') as f:
        result = chardet.detect(f.read())
    return result['encoding']


def ProfilePage(request):
    return render(request, 'profile.html')

def ContactPage(request):
    return render(request, 'contact.html')

def AboutPage(request):
    return render(request, 'about.html')
# views.py

def welcome_view(request):
    return render(request, 'welcome.html')

def welcome_about(request):
    return render(request, 'welcome_about.html')

def welcome_contact(request):
    return render(request, 'welcome_contact.html')

def view_files(request):
    excel_files = ExcelFile.objects.all()  # Assuming you have a model for files
    return render(request, 'view_files.html', {'excel_files': excel_files})








from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import get_object_or_404
from django.contrib.auth.views import PasswordResetConfirmView
from django.core.mail import send_mail
import random
import string

User = get_user_model()

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        uid = self.kwargs.get('uidb64')
        token = self.kwargs.get('token')
        user_pk = force_text(urlsafe_base64_decode(uid))
        user = get_object_or_404(User, pk=user_pk)

        if default_token_generator.check_token(user, token):
            new_password = generate_random_password()
            user.set_password(new_password)
            user.save()

            # Send the new password to the user
            self.send_new_password_email(user, new_password)
            return super().form_valid(form)
        else:
            return self.form_invalid(form)

    def send_new_password_email(self, user, new_password):
        subject = 'Your New Password'
        message = f'Hi {user.username},\n\nYour new password is: {new_password}\n\nPlease use this password to log in and change it once you are logged in.'
        from_email = 'your_email@example.com'
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # If the password has been generated, add it to the context for the template
        if 'new_password' in self.kwargs:
            context['new_password'] = self.kwargs['new_password']
        return context

def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

    
    

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # If the password has been generated, add it to the context for the template
        if 'new_password' in self.kwargs:
            context['new_password'] = self.kwargs['new_password']
        return context




from django.shortcuts import render, redirect
from .forms import ContactForm

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import ContactMessage
from .forms import ContactForm

def contact_view(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            # Save the form data to the database
            form.save()
            # Redirect to success page
            return redirect('contact_success')
    else:
        form = ContactForm()

    return render(request, 'contact.html', {'form': form})

def contact_success_view(request):
    return render(request, 'contact_success.html')



from django.conf import settings
from django.shortcuts import redirect, HttpResponse
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import google.auth
import gspread
import os
import pickle

# Define the scope for Google Sheets API
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']

def authorize(request):
    # Load credentials from the session or file
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
            
            # Save the credentials for future use
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
    
    # Store the credentials in the session
    request.session['credentials'] = creds.to_json()

    return redirect('get-google-sheet-data')

def get_google_sheet_data(request):
    # Load credentials from the session
    creds = None
    if 'credentials' in request.session:
        creds = google.oauth2.credentials.Credentials.from_authorized_user_info(
            info=request.session['credentials'])
    
    if not creds or not creds.valid:
        return redirect('authorize')

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
    
    # Use the credentials to access Google Sheets
    client = gspread.authorize(creds)
    spreadsheet_id = '1_5ttLMzZC0W0Samx0kyrqUh-UTt1GdKJx8yzTJRX1Xk'
    spreadsheet = client.open_by_key(spreadsheet_id)
    sheet = spreadsheet.sheet1
    data = sheet.get_all_records()
    return HttpResponse(data)

import matplotlib.dates as mdates
import datetime
import csv
import io
import base64
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
import plotly.graph_objs as go
from plotly.offline import plot

def display_csv(request, file_id):
    # Fetch the ExcelFile object
    excel_file = get_object_or_404(ExcelFile, id=file_id)

    # Read the CSV file and extract data
    days_data = []  # To store the time and PPG data for each day
    current_day_time = []
    current_day_ppg = []
    previous_time = None

    with open(excel_file.file.path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)  # Skip the header row explicitly
        
        for row in reader:
            try:
                # Assuming PPG is in the 3rd column (index 2) and Time is in the last column
                ppg_value = float(row[2])
                time_str = row[-1]  # Time in HH:MM:SS format

                # Convert time string to datetime object (add a dummy date to make it datetime)
                time_obj = datetime.datetime.strptime(time_str, "%H:%M:%S")

                # Detect a new day if the time decreases (previous day ends)
                if previous_time and time_obj.time() < previous_time.time():
                    # If we have valid data for the current day, store it
                    if current_day_time and current_day_ppg:
                        days_data.append((current_day_time, current_day_ppg))

                    # Reset for the next day
                    current_day_time = []
                    current_day_ppg = []

                previous_time = time_obj
                current_day_time.append(time_obj)
                current_day_ppg.append(ppg_value)

            except (ValueError, IndexError):
                # Skip rows with invalid PPG values or invalid time formats
                pass

        # Add the last day's data if it's not empty
        if current_day_time and current_day_ppg:
            days_data.append((current_day_time, current_day_ppg))

    # If no valid data is found, return an appropriate response
    if not days_data:
        return HttpResponse("No valid data found in the file.", status=400)

    # Create a list to hold Plotly plots for each day
    day_graphs = []

    for i, (time, ppg) in enumerate(days_data, start=1):
        # Ensure that time and ppg are not empty before processing
        if time and ppg:
            # Convert time list to Plotly-readable format (using string)
            time_strs = [t.strftime("%H:%M:%S") for t in time]

            # Create Plotly trace for each day's PPG data
            trace = go.Scatter(
                x=time_strs,
                y=ppg,
                mode='lines',
                name=f'Day {i} PPG vs Time',
                line=dict(color='blue')
            )

            # Define layout with full day on x-axis and zoom enabled
            layout = go.Layout(
                title=f'PPG vs Time - Day {i}',
                xaxis=dict(
                    title='Time (HH:MM:SS)',
                    range=['00:00:00', '23:59:59'],  # Full day range
                    tickformat='%H:%M:%S',
                    dtick=3600 * 1000,  # Tick every hour
                ),
                yaxis=dict(
                    title='PPG'
                ),
                hovermode='x',
            )

            # Create figure and plot it using Plotly
            fig = go.Figure(data=[trace], layout=layout)
            graph_div = plot(fig, output_type='div', include_plotlyjs=False)

            # Append the generated graph HTML for rendering in template
            day_graphs.append(graph_div)

    # Send the graphs to the template
    context = {
        'day_graphs': day_graphs,
        'file': excel_file
    }

    return render(request, 'display_csv.html', context)