from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/read-citizen-card', methods=['GET'])
def read_citizen_card():
    # Simulação de leitura do Cartão de Cidadão
    citizen_card_number = 'AB123456'  # Exemplo de número de Cartão de Cidadão lido
    return jsonify({'citizen_card_number': citizen_card_number})

if __name__ == '__main__':
    app.run(port=5001)
