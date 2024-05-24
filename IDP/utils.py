# utils.py

import random
from twilio.rest import Client
from flask import current_app

tokens = {}

def send_sms(to, token):
    client = Client(current_app.config['TWILIO_ACCOUNT_SID'], current_app.config['TWILIO_AUTH_TOKEN'])
    message = client.messages.create(
        body=f"Your authentication token is {token}",
        from_=current_app.config['TWILIO_PHONE_NUMBER'],
        to=to
    )
    return message.sid

def generate_token(length=6):
    return ''.join(random.choices('0123456789', k=length))

def store_token(user_id, token):
    tokens[user_id] = token

def validate_mobile_token(user, token):
    stored_token = tokens.get(user.id)
    return stored_token == token

def read_card_pin():
    # Implementar a lógica para leitura do cartão de cidadão
    # Aqui estamos apenas simulando a leitura
    return "1234"

def validate_card_pin(user, pin):
    card_pin = read_card_pin()
    return card_pin == pin
