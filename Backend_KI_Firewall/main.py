import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from flask import Flask, request, jsonify, Response
import logging
import requests


def injection_test_post(inputs, classifier):
    variables = inputs.split('&')
    values = []
    for variable in variables:
        values.append(variable.split(":"))
    print(values)
    mal = False
    for value in values:
        if classifier.predict(value).sum() > 0:
            mal = True 
            break
    
    if mal:
        return "MALICIOUS"

    return "NOT_MALICOUS"

def injection_test_get(inputs, classifier):
    variables = inputs.split('&')
    values = []
    for variable in variables:
        values.append(variable.split("="))
    print(values)
    mal = False
    for value in values:
        if classifier.predict(value).sum() > 0:
            mal = True 
            break
    
    if mal:
        return "MALICIOUS"

    return "NOT_MALICOUS"

classifier = pickle.load( open("data/tfidf_2grams_randomforest.p", "rb"))
logging.basicConfig(filename="ai_log.log", level=logging.ERROR)

TARGET_URL = 'http://localhost:3000/'
app = Flask(__name__)

# A single function to handle multiple routes and methods
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    # Extracting the request method
    method = request.method
    id = request.headers.get('id')
    query_params = request.args
    url_params = request.full_path

    # Handling GET request
    if method == 'GET':

        if len(query_params) > 0:
            result = injection_test_get(url_params, classifier)
            app.logger.error('%s, %s', id, result)
            if result == "NOT_MALICOUS":
                full_url = f'{TARGET_URL}{path}'
                resp = requests.get(full_url, params=request.args)
                return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))
        
            return Response("Forbidden Request", status=400)
        else:
            print("empty request")
            app.logger.error('%s, %s', id, "NOT_MALICIOUS")

            full_url = f'{TARGET_URL}{path}'
            resp = requests.get(full_url, params=request.args)
            return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    # Handling POST request
    elif method == 'POST':
        request_data = request.data

        if len(request_data) > 0:
            request_value = request_data.decode("utf-8")
            result = injection_test_post(request_value, classifier)
            app.logger.error('%s, %s', id, result)
            if result == "NOT_MALICOUS":
                full_url = f'{TARGET_URL}{path}'
                resp = requests.get(full_url, params=request.args)
                return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

            return Response("Forbidden Request", status=400)
        else:
            app.logger.error('%s, %s', id, "NOT_MALICIOUS")

            full_url = f'{TARGET_URL}{path}'
            resp = requests.get(full_url, params=request.args)
            return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

app.run(debug=True, port=5050, host='0.0.0.0')
