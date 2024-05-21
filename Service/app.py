from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/bank-page')
def bank():
    return render_template('bank.html')

@app.route('/medical-page')
def medical():
    return render_template('medical.html')

@app.route('/elearning-page')
def elearning():
    return render_template('elearning.html')

@app.route('/elearning-page/login')
def elearning_login():
    return render_template('elearning-login.html')

if __name__ == '__main__':
    app.run(debug=True)
