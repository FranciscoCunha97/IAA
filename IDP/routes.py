from flask import Blueprint, request, jsonify, redirect, render_template, url_for, flash, session
from werkzeug.security import check_password_hash
from models import add_user, get_user_by_email, create_tables, get_user_by_username, get_oauth2_client
from oauth import generate_authorization_code, validate_authorization_code, generate_token, validate_token, introspect_token, revoke_token


bp = Blueprint('main', __name__)

'''
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

'''
    
@bp.before_app_request
def initialize_database():
    create_tables()


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'GET':
        if 'user_id' not in session:
            return redirect(url_for('.login', next=request.url))

        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        client = get_oauth2_client(client_id)
        if not client:
            return jsonify({'error': 'Invalid client'}), 400

        user_id = session['user_id']
        code = generate_authorization_code(user_id, client_id, redirect_uri)
        return jsonify({'code': code})

    if request.method == 'POST':
        code = request.form.get('code')
        authorization_code = validate_authorization_code(code)
        if not authorization_code:
            return jsonify({'error': 'Invalid or expired code'}), 400

        access_token, refresh_token, expires_at = generate_token(authorization_code['user_id'], authorization_code['client_id'])
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token, 'expires_at': expires_at})


@bp.route('/oauth/token', methods=['POST'])
def token():
    access_token = request.form.get('access_token')
    token = validate_token(access_token)
    if not token:
        return jsonify({'error': 'Invalid or expired token'}), 400
    return jsonify({'user_id': token['user_id'], 'client_id': token['client_id'], 'expires_at': token['expires_at']})

@bp.route('/introspect', methods=['POST'])
def introspect_token_route():
    access_token = request.form.get('token')
    introspection = introspect_token(access_token)
    return jsonify(introspection)

@bp.route('/revoke', methods=['POST'])
def revoke_token_route():
    access_token = request.form.get('token')
    revoke_token(access_token)
    return jsonify({'status': 'success'})


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = get_user_by_email(email)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if get_user_by_email(email):
            flash('Email already exists', 'danger')
            return redirect(url_for('.register'))
        
        if get_user_by_username(username):
            flash('Username already exists', 'danger')
            return redirect(url_for('.register'))

        add_user(username, email, password)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('.login'))
    
    return render_template('register.html')


# Rota para ler o Cartão de Cidadão e PIN

'''
@bp.route('/read-citizen-card', methods=['GET'])
def read_citizen_card():
    result, error = read_citizen_card_data()
    if error:
        print(error)
        return jsonify({'error': error}), 400
    return jsonify(result)

'''

