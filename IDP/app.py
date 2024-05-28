from flask import Flask
from config import Config
from routes import bp

app = Flask(__name__)
app.config.from_object(Config)
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run(debug=True)
