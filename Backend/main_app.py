import ast
import datetime
import os
from functools import wraps

import custom_exceptions
import jwt
import mysql_functionality
import pymysql
from flask import Flask, jsonify, make_response, request, g
from flaskext.mysql import MySQL
from general_utilities import generate_token

template_dir = os.path.abspath('templates')
static_dir = os.path.abspath('static')
print(template_dir)
restServer = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
mysql = MySQL()
restServer.config.from_object("config.DefaultConfig")
mysql.init_app(restServer)
connection_pool = mysql_functionality.MySQLConnectionPool(mysql, max_connections=5)
connection = mysql_functionality.GymDiaryFlaskApp(connection_pool)


def requires_user_token(f):
	@wraps(f)
	def tokenised(*args, **kwargs):
		token = request.args.get('token')
		if not token:
			return jsonify({'response': 'Token is missing'}), 403
		try:
			data = jwt.decode(token, restServer.config['USER_SECRET_KEY'], algorithms=["HS256"])
		# Triggers on invalid Token format
		except jwt.exceptions.DecodeError:
			return jsonify({'response': 'Token is invalid'}), 403
		
		# Triggers when current time has passed token expiration.
		except jwt.ExpiredSignatureError:
			return jsonify({'response': 'Token has expired'}), 401
		return f(*args,**kwargs)
	return tokenised


def requires_admin_token(f):
        @wraps(f)
        def tokenised(*args, **kwargs):
                token = request.args.get('token')
                if not token:
                        return jsonify({'response': 'Token is missing'}), 403
                try:
                        data = jwt.decode(token, restServer.config['ADMIN_SECRET_KEY'], algorithms=["HS256"])
                except jwt.exceptions.DecodeError:
                        return jsonify({'response': 'Token is invalid'}), 403
                except jwt.ExpiredSignatureError:
                        return jsonify({'response': 'Token has expired'}), 401
                return f(*args,**kwargs)
        return tokenised

@restServer.after_request
def after_request(response):
	response.headers.add('Access-Control-Allow-Origin', '*')
	response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
	response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
	return response

@restServer.route("/check_user_token")
@requires_user_token
def test():
        return make_response('Token is valid', 200)

@restServer.route("/check_admin_token")
@requires_admin_token
def test2():
        return make_response('Token is valid', 200)

'''@restServer.route("/dbgetusernames", methods=['GET'])
@requires_admin_token
def get_usernames():
        connection.get_database_tables()
        return jsonify(connection.get_usernames())'''

@restServer.route("/get_user", methods=['GET'])
@requires_user_token
def get_user_record():
	username = request.args.get('username')
	record = connection.get_user_record(username)
	return jsonify(record)
	
@restServer.route("/login", methods=['GET', 'POST'])
def user_login():   
        try:   
                # Return failed authentication msg if user credentials don't match
                if not (request.authorization and connection.credentials_valid(request.authorization.username, request.authorization.password)):
                        return make_response('Authorization failed', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})
                is_admin = connection.is_admin(connection, request.authorization.username)

                # Generate tokens
                JSON_object = {'token': '', 'admin_token': ''}
                if is_admin:
                        JSON_object['admin_token'] = generate_token(request.authorization.username, restServer.config['ADMIN_SECRET_KEY'])
                JSON_object['user_token'] = generate_token(request.authorization.username, restServer.config['USER_SECRET_KEY']) 
                
                return jsonify(JSON_object)
        except TypeError as e:
               print(e)
               return make_response('Authorization failed', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})
               
                
@restServer.route("/register", methods=['POST'])
def user_registration():
        username = request.form['username']
        password = request.form['password']
        forename = request.form['forename']
        surname = request.form['surname']
        try:
                connection.add_user(username, password, forename, surname)
                return make_response('Registration Successful', 201)
        except custom_exceptions.UserExistsException:
                return make_response('Account already exists', 409)


@restServer.route("/get_tables", methods=['GET'])
@requires_user_token
def get_database_tables():
        return jsonify(connection.get_database_tables())


@restServer.route("/get_entry_count", methods=['GET'])
@requires_user_token
def get_entry_count():
        username = request.args.get("username")
        return jsonify(connection.get_diary_entry_count(username))

    
@restServer.route("/get_memberships", methods=['GET'])
@requires_user_token
def get_memberships():
        username = request.args.get("username")
        memberships = connection.get_gym_memberships(username)
        return jsonify(memberships)

@restServer.route("/register_membership", methods=['POST'])
@requires_user_token
def add_membership():
    username = request.form['username']
    postcode = request.form['postcode']
    response = connection.add_user_gym_association(connection, username, postcode)
    if response['state'] != 'successful':
        return make_response({'response': response['state']}, 409)
    return make_response({'response': 'Membership registration successful'}, 201)
    
    
@restServer.route("/get_workout_dates", methods=['GET'])
@requires_user_token
def get_workout_dates():
        username = request.args.get("username")
        membership = request.args.get("gym_membership")
        workout_dates = connection.get_membership_workouts(username, membership)
        return jsonify(workout_dates)

@restServer.route("/get_membership_workout_dates", methods=['GET'])
@requires_user_token
def get_workout_dates2():
        username = request.args.get("username")
        workout_dates = connection.get_gym_workouts(username)
        return jsonify(workout_dates)
    
@restServer.route("/get_diary_entries", methods=['GET'])
@requires_user_token
def get_diary_entries():
        username = request.args.get("username")
        gym_postcode = request.args.get("gym_membership")
        workout_date = request.args.get("workout_date")
        diary_entries = connection.get_workout_diary_entries(username, gym_postcode, workout_date)
        return jsonify(diary_entries)
    
@restServer.route("/get_all_user_diary_entries", methods=['GET'])
@requires_user_token
def get_all_diary_entries():
    username = request.args.get("username")
    diary_entries = connection.get_all_user_diary_entries(username)
    return jsonify(diary_entries)
    
    
    
@restServer.route("/add_diary_entries", methods=['POST'])
@requires_user_token
def add_diary_entries():
        # Get diary entries and convert the string to a dict
        post_dict = ast.literal_eval(request.form['diary_entries'])
        if (len(post_dict) == 0):
                return make_response('No data sent', 400)
        try:
            connection.add_diary_entries(*post_dict)
            return make_response('success', 200)
        except custom_exceptions.MissingFieldException:
            return make_response('Fields are missing, ensure they are entered.', 422)
        except pymysql.err.IntegrityError:
            return make_response('A submitted entry already exists, remove it and try again', 409)
        except pymysql.err.OperationalError as error:
            return make_response(error.args[1], 400)
 
@restServer.route("/delete_diary_entries", methods=['POST'])
@requires_user_token
def delete_diary_entries():
    diary_entries_IDs = ast.literal_eval(request.form['diary_entries'])
    entry_IDs = [entry['entry_ID'] for entry in diary_entries_IDs]
    
    connection.delete_diary_entries(*entry_IDs)
    return make_response("Deletion successful", 200)


@restServer.route("/add_workout", methods=['POST'])
@requires_user_token
def add_workout():
    # Get workout date
    workout_date = request.form['workout_date']
    membership = request.form['membership']
    username = request.form['username']
    try:
        connection.add_workout(workout_date, username, membership)
    except custom_exceptions.WorkoutExistsException as error:
        return make_response(str(error.args[0]), 409)
    except TypeError as e:
        return make_response('No membership selected, please ensure you have a registered membership', 409)
    return make_response('Workout registered', 200)
    

@restServer.route("/get_exercises", methods=['GET'])
@requires_user_token
def get_exercise_names():
        exercises = connection.get_exercises()
        return jsonify(exercises)


@restServer.route("/delete_workout", methods=['POST'])
@requires_user_token
def delete_workout():
        workout_ID = request.form['workout_ID']
        connection.remove_workout(workout_ID)
        return make_response('Workout Deleted', 200)

@restServer.route('/update_account_information', methods=['POST'])
@requires_user_token
def update_account():
    user_ID = request.form['user_ID']
    username = request.form['username']
    new_username = request.form['new_username']
    forename = request.form['forename']
    surname = request.form['surname']
    if not user_ID:
        make_response('Account not found', 404)
    try:
        connection.update_account_information(user_ID=user_ID, username=new_username, forename=forename, surname=surname)
    except pymysql.err.IntegrityError:
        return make_response("Username already taken, try a different one", 409)
    return make_response('Account updated', 200)


@restServer.route('/update_diary_entries', methods=['POST'])
@requires_user_token
def update_diary_entries():
    diary_entries = ast.literal_eval(request.form['diary_entries'])
    try:
        connection.update_multiple_diary_entries(diary_entries)
    except pymysql.err.IntegrityError:
        return make_response("One attempted record update already exists", 409)
    return make_response("Diary Entries Updated", 200) 
    
@restServer.route('/delete_membership', methods=['POST'])
@requires_user_token
def delete_membership():
    user_gym_ID = request.form['ID']
    connection.delete_membership(user_gym_ID)
    return make_response("Membership deleted", 200)

@restServer.route('/get_muscle_groups', methods=['GET'])
@requires_admin_token
def get_muscle_groups():
    muscle_groups = connection.get_muscle_groups()
    print(muscle_groups)
    return jsonify(muscle_groups)

@restServer.route('/add_exercises', methods=['POST'])
@requires_admin_token
def add_exercises():
    exercises = ast.literal_eval(request.form['exercises'])
    exercises_list = [record['exercise'] for record in exercises]
    print(exercises_list)
    try:    
        connection.add_exercises(*exercises_list)
    except pymysql.err.IntegrityError:
        return make_response('One or more exercises already exist, try different exercises', 409)
    return make_response('Exercises added', 200)

@restServer.route('/add_admin_account', methods=['POST'])
@requires_admin_token
def add_admin_account():
    username = request.form['username']
    user_ID = connection.get_user_record(username)['ID']
    if not user_ID:
        return make_response("Account associated with username %s not found, try a different username" % username, 404)
    try:
        connection.add_admin_account(user_ID, username)
    except pymysql.err.IntegrityError:
        return make_response("Account is already an administrator, try a different one", 409)
    return make_response('Admin account added', 200)

if __name__ == '__main__':
        print("== Running in debug mode ==")
        restServer.run(host='ysjcs.net', port=5004, debug=True)
