import smtplib
from email.message import EmailMessage

from app.config import settings


def send_mail(to: str, subject: str, body: str) -> None:
    """Envoie un email texte brut (Mailhog en dev, un vrai relais SMTP en prod).

    Appel bloquant (smtplib) : à lancer via `asyncio.to_thread` depuis un handler async.
    """
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
        smtp.send_message(message)
