from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SentecesDatabase
users = db["Users"]

def verifyUser(username, password):
    hashed = users.find({f"Username": username})[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed) == hashed:
        return True
    return False

def countTokens(username):
    tokens = users.find({"Username": username}, {"Tokens": 1, "_id": 0})[0]["Tokens"]
    return int(tokens)

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Sentence": "",
            "Tokens": 6
        })

        retJson = {
            "status_code": 200,
            "msg": "Você se cadastrou na API."
        }
        return retJson
    
class Store(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]

        correct_pw = verifyUser(username, password)

        if not correct_pw:
            retJson = {
                'status_code': 302,
                'msg': "Invalid username ow password"
            }
            return retJson
        
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                'status_code': 301,
                'msg': "Out of tokens."
            }
            return retJson
        
        users.update_one({"Username": username}, {"$set": {"Sentence": sentence, "Tokens": num_tokens-1}})

        retJson = {
            'status_code': 200,
            'msg': "Sentence saved sucessfully"
        }
        return retJson

class Retrive(Resource):
    def get(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        correct_pw = verifyUser(username, password)

        if not correct_pw:
            retJson = {
                "status_code": 302,
                "msg": "Invalid username or password"
            }
            return retJson
        
        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                'status_code': 301,
                'msg': "Out of tokens."
            }
            return retJson
        
        users.update_one({"Username": username}, {"$set": {"Tokens": num_tokens-1}})

        sentence = users.find({"Username": username})[0]["Sentence"]
        
        retJson = {
            'sentence': sentence
        }
        return retJson

        

api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Retrive, '/retrive')

@app.route('/')
def hello():
    return "Hello World!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


#Register
#Store
#Retrieve