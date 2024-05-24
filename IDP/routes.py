# routes.py

from flask import Blueprint, request, jsonify, redirect, render_template, url_for, session, current_app
from werkzeug.security import check_password_hash
from models import db, User, OAuth2Client
from oauth import authorization
from utils import generate_token, send_sms, store_token, validate_mobile_token, validate_card_pin

bp = Blueprint('main', __name__)

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
            send_sms(user.username, token)  # Assumindo que o username é o número de telefone
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
                if not validate_card_pin(user, pin):
                    return jsonify({'error': 'Invalid PIN'}), 403

            return authorization.create_authorization_response(grant_user=user)
        return authorization.create_authorization_response(grant_user=None)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            next_url = request.args.get('next') or url_for('.index')
            return redirect(next_url)
        return jsonify({'error': 'Invalid credentials'}), 401
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

#@bp.route('/register', methods=['GET', 'POST'])
#def register():
#    if request.method == 'POST':
#        username = request.form.get('username')
#        password = request.form.get('password')
#        user = User(username=username, password=generate_password_hash(password))
#        db.session.add(user)
#        db.session.commit()
#        return redirect(url_for('.login'))
#    return render_template('register.html')

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
