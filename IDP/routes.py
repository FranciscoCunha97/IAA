from flask import Blueprint, request, jsonify, redirect, render_template, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, OAuth2Client
from oauth import authorization
from utils import generate_token, send_sms, store_token, validate_mobile_token, validate_card_pin
from smartcard.System import readers
from smartcard.util import toHexString

bp = Blueprint('main', __name__)

def read_citizen_card_data():
    try:
        r = readers()
        if len(r) < 1:
            return None, "Nenhum leitor de cartões encontrado"

        reader = r[0]
        connection = reader.createConnection()
        connection.connect()

        # Comando APDU para selecionar o cartão (ajuste conforme necessário)
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x01]

        # Enviar comando APDU
        data, sw1, sw2 = connection.transmit(SELECT)
        if sw1 == 0x90 and sw2 == 0x00:
            # Leitura do número do cartão e PIN (ajuste conforme necessário)
            READ_CARD = [0x00, 0xB0, 0x00, 0x00, 0x10]
            data, sw1, sw2 = connection.transmit(READ_CARD)
            citizen_card_number = toHexString(data)
            pin = '1234'  # Simulação de leitura do PIN (substitua pela leitura real)
            return {'citizen_card_number': citizen_card_number, 'pin': pin}, None
        else:
            return None, "Falha ao ler o cartão"
    except Exception as e:
        return None, str(e)

@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()

@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        if 'user_id' not in session:
            return redirect(url_for('.login', next=request.url))

        client_id = request.args.get('client_id')
        client = OAuth2Client.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify({'error': 'Invalid client'}), 400

        user = User.query.get(session['user_id'])

        if client.criticality_level == 'medium':
            # Enviar token via SMS
            token = generate_token()
            send_sms(user.phone, token)
            store_token(user.id, token)
        
        return render_template('authorize.html', user=user, request=request, criticality_level=client.criticality_level)

    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 403

        client_id = request.form.get('client_id')
        client = OAuth2Client.query.filter_by(client_id=client_id).first()
        if not client:
            return jsonify({'error': 'Invalid client'}), 400

        user = User.query.get(session['user_id'])
        grant_user_consent = request.form.get('confirm', 'no')
        if grant_user_consent == 'yes':
            # Verificação adicional baseada no nível de criticidade
            if client.criticality_level == 'medium':
                token = request.form.get('token')
                if not validate_mobile_token(user, token):
                    return jsonify({'error': 'Invalid mobile token'}), 403
            elif client.criticality_level == 'high':
                pin = request.form.get('pin')
                citizen_card = request.form.get('citizen_card')
                if user.citizen_card != citizen_card or not validate_card_pin(user, pin):
                    return jsonify({'error': 'Invalid PIN or Citizen Card'}), 403

            return authorization.create_authorization_response(grant_user=user)
        return authorization.create_authorization_response(grant_user=None)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            next_url = request.args.get('next') or url_for('.index')
            return redirect(next_url)
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@bp.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('.index'))

@bp.route('/')
def index():
    return render_template('home.html')

@bp.route('/bank-page')
def bank_page():
    return render_template('bank.html')

@bp.route('/medical-page')
def medical_page():
    return render_template('medical.html')

@bp.route('/elearning-page')
def elearning_page():
    return render_template('elearning.html')

@bp.route('/bank-page/login')
def bank_login():
    return render_template('login.html')

@bp.route('/medical-page/login')
def medical_login():
    return render_template('login.html')

@bp.route('/elearning-page/login')
def elearning_login():
    return render_template('login.html')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists', 'danger')
            return redirect(url_for('.register'))

        user = User(
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('.login'))
    
    return render_template('register.html')



@bp.route('/introspect', methods=['POST'])
def introspect_token():
    token = request.form.get('token')
    introspection = authorization.introspect_token(token)
    return jsonify(introspection)

@bp.route('/revoke', methods=['POST'])
def revoke_token():
    token = request.form.get('token')
    authorization.revoke_token(token)
    return jsonify({'status': 'success'})

# Rota para ler o Cartão de Cidadão e PIN

@bp.route('/read-citizen-card', methods=['GET'])
def read_citizen_card():
    result, error = read_citizen_card_data()
    if error:
        print(error)
        return jsonify({'error': error}), 400
    return jsonify(result)

