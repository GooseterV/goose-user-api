import base64
import datetime
import json
import os
import random
import secrets
import sqlite3

import dotenv
import jwt
import pandas as pd
from functools import wraps
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


dotenv.load_dotenv()



app = Flask(__name__)

app.config["ENCODE_KEY"] = os.getenv("ENCODING_KEY")

app.config["users"] = [

]

app.config["admins"] = [

]

b26chars = list("abcdefghijklmnopqrstuvwxyz")
b52chars = b26chars + [c.upper() for c in b26chars]
b62chars = b52chars + [str(i) for i in range(0, 10)]
b64chars = b62chars + list("+=")
hexchars = list("abcdef0123456789")
for l in [b26chars, b52chars, b62chars, b64chars, hexchars]:
	random.shuffle(l)

def dict_factory(cursor, row):
	d = {}
	for idx, col in enumerate(cursor.description):
		d[col[0]] = row[idx]
	return d

def get_users():
	conn = sqlite3.connect("py/users.db")
	conn.row_factory = dict_factory
	c = conn.cursor()
	c.execute("SELECT * FROM users")
	usersJSON = c.fetchall() 
	[d.pop("index") for d in usersJSON]
	#[d.pop("level_0") for d in usersJSON]
	return usersJSON

def jwt_encode(userid:str):
	t = {
		'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=1800),
		'public_id': userid
	}
	return jwt.encode(
		t,
		app.config["ENCODE_KEY"],
		algorithm='HS256'
	)

def jwt_decode(token):
	t = jwt.decode(token, app.config["ENCODE_KEY"], algorithms=['HS256'])
	return t['public_id']

def token_auth(fn):
	@wraps(fn)
	def wrapper():
		token = None
		if 'Authorization' in list(request.headers.keys()):
			token = request.headers['Authorization']
			if token == None:
				return json.dumps({"success":False, "message":"Failed authorization."}), 401
			elif token != None:
				try:
					uid = jwt_decode(token)
				except Exception as e:
					return {"success":False, "message":"Something went wrong. The token may be invalid."}, 400
				return fn()
		elif 'Authorization' not in list(request.headers.keys()):
			return json.dumps({"success":False, "message":"Failed authorization."}), 401
		
	return wrapper

def admin_only(fn):
	@wraps(fn)
	def wrapper():
		token = request.headers['Authorization']
		uid = jwt_decode(token)
		if uid not in app.config["admins"]:
			return json.dumps({"success":False, "message":"Permission Denied."}), 403
		elif uid in app.config["admins"]:
			return fn()
		


@app.route('/string', defaults={"chars":",".join(b62chars), "length":16})
def random_string(chars, length):
	chars = request.args.get("chars", default=",".join(b62chars)).split(",")
	length = int(request.args.get("length", default="16"))
	random.shuffle(chars)
	return "".join([c for c in random.choices(chars, k=length)])


@app.route('/users/new', methods=['POST'])
def create_user():
	payload = json.loads(request.get_data())
	userExists = len(list(filter(lambda u: u["name"] == payload["name"], get_users())))!=0
	correctParams = "name" in payload.keys() and "password" in payload.keys()
	if correctParams and not userExists:
		id = secrets.token_hex(12)
		user = {
			"name":payload["name"],
			"id":id,
			"created":datetime.datetime.utcnow().timestamp()
		}
		token = jwt_encode(id)
		app.config["users"].append(user)
		conn = sqlite3.connect("py/users.db")
		c = conn.cursor()
		df = pd.DataFrame([{
			"name":payload["name"],
			"id":id,
			"created":datetime.datetime.utcnow().timestamp(),
			"password":generate_password_hash(payload["password"])
		}])
		df.to_sql("users", conn, if_exists="append")
		return json.dumps({"success":True, "message":"Successfully created account.", "auth_token":token}), 200
	elif userExists:
		return json.dumps({"success":False, "message":"Name already taken."}), 201
	elif not correctParams:
		return json.dumps({"success":False, "message":"Invalid parameters."}), 400



@app.route('/users/byid', methods=['GET'])
def get_user():
	all_users = json.loads(get_all_users()[0])
	userid = request.args.get("userid")
	userExists = len(list(filter(lambda u: u["name"] == userid, all_users)))!=0
	if userExists:
		user = list(filter(lambda user: user["id"] == userid, all_users))[0]
		return json.dumps({"success":True, "data":user}), 200
	elif not userExists:
		return json.dumps({"success":False, "message":"User does not exist."}), 404

@app.route('/users', methods=['GET'])
@app.route('/users/all', methods=['GET'])
@token_auth
@admin_only
def get_all_users():
	usersJSON = get_users()
	return json.dumps({"success":True, "data":usersJSON}), 200

@app.route('/users/edit', methods=['PUT'])
@token_auth
def edit_user():
	all_users = get_users()
	payload = json.loads(request.get_data())
	head = request.headers
	userid = payload["userid"]
	updated_users = [{"name":payload["name"], "id":userid, "created":user["created"], "password":user["password"]} if user["id"] == userid else user for user in all_users]
	conn = sqlite3.connect("py/users.db")
	c = conn.cursor()
	df = pd.DataFrame(updated_users)
	df.to_sql("users", conn, if_exists="replace")
	user = list(filter(lambda user: user["id"] == userid, get_users()))[0]
	return json.dumps(user), 200

app.run(port=8000)
