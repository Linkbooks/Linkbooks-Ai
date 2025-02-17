import logging
import os
from flask_mail import Message, Mail
from flask import current_app

# Initialize Flask-Mail
mail = Mail()


def init_mail(app):
    """
    Initializes the Flask-Mail extension.
    Call this in your app factory.
    """
    app.config.update(
        MAIL_SERVER=os.getenv('MAIL_SERVER', 'smtp.gmail.com'),
        MAIL_PORT=int(os.getenv('MAIL_PORT', 587)),
        MAIL_USE_TLS=os.getenv('MAIL_USE_TLS', 'True') == 'True',
        MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_DEFAULT_SENDER', 'no-reply@linkbooksai.com')
    )
    mail.init_app(app)


def send_verification_email(email, token):
    """
    Sends a verification email with a unique token.

    :param email: User's email address
    :param token: Unique verification token
    """
    try:
        verification_link = f"https://linkbooksai.com/verify-email?token={token}"
        msg = Message(
            subject="Verify Your Email Address",
            recipients=[email],
            html=f"""
                <html>
                    <body>
                        <p>Hello,</p>
                        <p>Thank you for subscribing to LinkBooksAI!</p>
                        <p>Please verify your email address by clicking the link below:</p>
                        <p><a href="{verification_link}" style="color: blue; font-weight: bold;">Verify Email</a></p>
                        <p>This link will expire in 24 hours.</p>
                        <p>If you did not subscribe, please ignore this email.</p>
                    </body>
                </html>
            """
        )

        with current_app.app_context():  # Ensures it runs within Flask context
            mail.send(msg)

        logging.info(f"✅ Verification email sent to {email}.")
    
    except Exception as e:
        logging.error(f"❌ Failed to send email to {email}: {e}")
        raise Exception("Email sending failed.")
