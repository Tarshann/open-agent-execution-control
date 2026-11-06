import smtplib
import requests


def notify(addr, body):
    with smtplib.SMTP("localhost") as s:
        s.sendmail("a@example.test", [addr], body)


def post_webhook(url, payload):
    return requests.post(url, json=payload)
