import smtplib
from email.mime.text import MIMEText

# SMTP Configuration for TLS (Port 587)
SMTP_SERVER = 'smtp.zoho.com'
SMTP_PORT = 587  # Port for TLS/STARTTLS
EMAIL_USERNAME = 'no-reply@waw.group'  # Replace with your full Zoho email address
EMAIL_PASSWORD = '7Fj1QWesB0Cb'  # App-specific password from Zoho

# Compose the email
msg = MIMEText('This is a test email to verify SMTP configuration with TLS.')
msg['Subject'] = 'Test Email (TLS)'
msg['From'] = EMAIL_USERNAME
msg['To'] = 'samueloliversiegel@gmail.com'  # Replace with your test recipient email

try:
    # Establish connection to SMTP server using TLS
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.ehlo()  # Identify ourselves to the SMTP server
        server.starttls()  # Upgrade the connection to a secure encrypted connection using TLS
        server.ehlo()  # Re-identify ourselves over the TLS connection
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)  # Authenticate with your credentials
        # Update the `sendmail` function call with correct recipient email
        server.sendmail(EMAIL_USERNAME, ['samueloliversiegel@gmail.com'], msg.as_string())
    print("Email sent successfully using TLS!")
except Exception as e:
    print(f"Failed to send email using TLS: {e}")
