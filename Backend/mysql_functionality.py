from flask import jsonify, Response, g
import pymysql
from pymysql.cursors import Cursor, DictCursor
from pymysql.connections import Connection
from functools import wraps
from general_utilities import is_valid_date
import custom_exceptions
import bcrypt 
from flaskext.mysql import MySQL
from queue import Queue


# Adapted from Bing Chat AI code, prompt: 'Generate a python class that implements a connection pool, utilising the Flask-MySQL library'
# Added max connection functionality with the prompt: 'can you implement a max connection number to the generated pool class'
class MySQLConnectionPool:
    pool: MySQL
    max_connections: int
    current_connections: int

    def __init__(self, mysql: MySQL, max_connections=5):
        self.pool = mysql
        self.max_connections = max_connections
        self.current_connections = 0
        self.connection_request_queue = Queue()

    # Provide a Connection object from the pool, if no connections available, wait for free connection then return it
    def get_connection(self):
        if self.current_connections < self.max_connections:
            self.current_connections += 1
            return self.pool.connect()
        else:
            return self.connection_request_queue.get()

    # Close provided connection, and provide a new one that can be passed on to functions in the request queue
    def close_connection(self, conn: Connection):
        conn.close()
        self.current_connections -= 1
        if not self.connection_request_queue.empty():
            self.connection_request_queue.put(self.pool.connect())

    # Add a request for a connection to a queue
    def request_connection(self):
        self.connection_request_queue.put(None)
        

# Wrapper to handle MySQL queries, abstracts connections and cursors from query calls
def cursor_handled(is_DML: bool = False):
    def cursor_decorator(func):
        def wrapper(self, *args, **kwargs):
            # Request connection
            self.conn_pool.request_connection()
            # Get connection / Wait until one is free
            connection = self.conn_pool.get_connection()
            cursor = connection.cursor(DictCursor)
            result = func(cursor, *args, **kwargs)
            if is_DML:
                connection.commit()
            cursor.close()
            self.conn_pool.close_connection(connection)
            return result
        return wrapper
    return cursor_decorator

# Handles basic MySQL queries, abstracts some writing of queries and retrieving records
class FlaskMySQLConnection():
    conn_pool: MySQLConnectionPool
    database_name: str


    def __init__(self, mysql_connection_pool, database_name: str):
        self.conn_pool = mysql_connection_pool
        self.database_name = database_name


    # --- Exists statements --- #

    # Check if data exists in the database, used as base for other exists checkers
    @cursor_handled()
    def is_data_in_table_column(cursor: DictCursor, self, table_name: str, selected_column: str, *possible_values):
        query = StatementGenerator.generate_is_data_in_table_statement(self.database_name, table_name, selected_column, len(possible_values))
        cursor.execute(query, *possible_values,)
        result = cursor.fetchone()
            
        return bool(result['record_exists'])


    # --- Create Statements --- #

    # Add a subgke record to a specified table
    @cursor_handled(True)
    def add_record_to_table(cursor: DictCursor, self, table: str, **record) -> None:
        query = StatementGenerator.generate_record_insert_statement(self.database_name, table, *record.keys())
        cursor.execute(query, [*record.values(),])
        
    # Generic method for sending an INSERT statement to the database
    @cursor_handled(True)
    def insert_statement(cursor: DictCursor, self, query: str, items: list) -> None:
        cursor.execute(query, items)
        
    # --- Read Statements --- #

    # Return records searching one column for one value
    @cursor_handled()
    def single_column_record_select(cursor: DictCursor, self, table_name: str, search_column: str, data: object, *return_columns: str) -> object:
        query = StatementGenerator.generate_n_field_single_record_select(self.database_name, table_name, search_column, *return_columns,)
        cursor.execute(query, data)
        record = cursor.fetchone()
        
        try:
            return record
        except TypeError:
            return None
    
    # Generic function for getting data from the database
    @cursor_handled()
    def select_statement(cursor: DictCursor, self, query: str, *data: object):
        if len(data) == 0:
            cursor.execute(query)
        else:
            cursor.execute(query, data)
        records = cursor.fetchall()
        return records
    
    # Method for selecting one record from a specified query
    @cursor_handled()
    def single_select_statement(cursor: DictCursor, self, query: str, *data: object):
        cursor.execute(query, *data,)
        record = cursor.fetchone()
        return record
    
    # Get and Return a list of the tables in the given database
    @cursor_handled()
    def get_tables(cursor: DictCursor, self):
        cursor.execute("SHOW TABLES")
        records = cursor.fetchall()
        return records

    # --- Update Statements --- #

    # For updating a single record
    @cursor_handled(True)
    def single_record_update_statement(cursor: DictCursor, self, database_name: str, table_name: str, id_column_name: str, record_ID: any, **field_updates):
        # Generate update query string
        query = StatementGenerator.generate_single_record_update_statement(database_name, table_name, id_column_name, record_ID, len(field_updates.values()))
        # Flattend the kwargs to fit as placeholders into the query
        flattened_field_updates = []
        for key, value in field_updates.items():
            flattened_field_updates.append(key)
            flattened_field_updates.append(value)
        
        cursor.execute(query.format(*field_updates.keys(),), list(field_updates.values()))
        
    # For updating multiple records
    @cursor_handled(True)
    def multiple_record_update_statement(cursor: DictCursor, self, database_name: str, table_name: str, id_column_name: str, *records):
        # records wraps itself in another array for no apparent reason, this fixes it.
        records = records[0]
        for record in records:
            record_ID = record['ID']
            del record['ID']
            query = StatementGenerator.generate_single_record_update_statement(database_name, table_name, id_column_name, record_ID, len(record.keys()))
            cursor.execute(query.format(*record.keys(),), list(record.values()))
                            

    # --- Delete Statements --- #

    # Delete a single row from a specified table in a specified database
    @cursor_handled(True)
    def single_record_delete(cursor: DictCursor, self, table_name: str, unique_identifier: any):
        cursor.callproc("benjaminclough_COM6009M.single_column_delete_by_ID", [table_name, unique_identifier])

    # Delete multiple rows from specified table
    @cursor_handled(True)
    def multiple_record_delete(cursor: DictCursor, self, table_name: str, *unique_identifiers: any):
        for ID in unique_identifiers:
            cursor.callproc("benjaminclough_COM6009M.single_column_delete_by_ID", [table_name, ID])

# Class of useful functionality of building SQL statements
class StatementGenerator:

    @staticmethod
    # Generate INSERT statement for one record
    def generate_record_insert_statement(database_name: str, table_name: str, *columns) -> str:
        query = f"""INSERT INTO {database_name}.{table_name} {*columns,} VALUES (%s)""".replace("'", "")
        if len(columns) == 1:
            query = f"""INSERT INTO {database_name}.{table_name} ({columns[0]}) VALUES (%s)""".replace("'", "")
        string_values = StatementGenerator.generate_replacement_strings(count=len(columns))
        return query % string_values

    @staticmethod
    # Generate INSERT statement for multiple records
    def generate_multiple_record_insert_statement(database_name: str, table_name: str, record_count: int, *columns) -> str:
        query = f"""INSERT INTO {database_name}.{table_name} {*columns,} VALUES %s""".replace("'", "")
        replacement_values_string = StatementGenerator.generate_multiple_record_VALUES_string(len(columns), record_count)
        return query % replacement_values_string

    @staticmethod
    # Generate statement to check if data is in a column in a table in a database
    def generate_is_data_in_table_statement(database_name: str, table_name: str, selected_column: str, value_count: int) -> bool:
        string_values = StatementGenerator.generate_replacement_strings(count=value_count)
        query = f"""SELECT COUNT({selected_column}) AS record_exists FROM {database_name}.{table_name} WHERE {selected_column} IN ({string_values})"""
        return query
    
    @staticmethod
    # Generate statement to get single field of information from database
    def generate_n_field_single_record_select(database_name: str, table_name: str, search_column: str, *return_columns: str):
        formatted_return_columns = StatementGenerator.generate_replacement_strings(len(return_columns)) % (*return_columns,)
        query = f"""SELECT {formatted_return_columns} FROM {database_name}.{table_name} WHERE {search_column} = %s""".replace("'", "")
        return query

    @staticmethod
    # Generate a single record update statement
    def generate_single_record_update_statement(database_name: str, table_name: str, id_column_name: str, record_ID: any, field_updates_count: int):
        query = """UPDATE `%s`.`%s` SET %s WHERE `%s` = %s"""
        replacement_strings = StatementGenerator.generate_equality_replacement_strings(field_updates_count)

        return query % (database_name, table_name, replacement_strings, id_column_name, record_ID)
        

    @staticmethod
    # Generate VALUES strings dyamically for multiple reords
    def generate_multiple_record_VALUES_string(column_count, record_count) -> str:
        basic_replacement_strings = StatementGenerator.generate_replacement_strings(column_count)
        replacement_record = f"({basic_replacement_strings})"
        if record_count < 2:
            return replacement_record

        replacement_records = f"{replacement_record}, " * (record_count - 1)
        replacement_records += replacement_record

        return replacement_records      
    
    @staticmethod
    # Generate %s statements
    def generate_replacement_strings(count: int) -> str:
        if count < 2:
            return '%s'
        
        replacement_string = "%s, " * (count - 1)
        replacement_string += "%s"
        return replacement_string

    @staticmethod
    # Generate {} = %s statements
    def generate_equality_replacement_strings(count: int) -> str:
        if count < 2:
            return '%s = %s'
        
        replacement_string = "{} = %s, " * (count - 1)
        replacement_string += "{} = %s"

        return replacement_string

# For handling all of the GymDiary specific MySQL queries
class GymDiaryFlaskApp(FlaskMySQLConnection):
    def __init__(self, connection: Connection) -> None:
        super().__init__(connection, "benjaminclough_COM6009M")

    # --- Create Functionality --- #

    # Add a user to the users table
    def add_user(self, username: str, password: str, forename: str, surname: str) -> None:
        if self.is_user(username):
            raise custom_exceptions.UserExistsException(username)
        
        salt = bcrypt.gensalt()
        encoded_password = password.encode('utf-8')
        encrypted_password = bcrypt.hashpw(encoded_password, salt)
        super().add_record_to_table(self, table="users", username=username, password=encrypted_password, forename=forename, surname=surname)

    # Add gym to gyms table
    def add_gym(self, gym_name: str, gym_city: str, gym_postcode) -> None:
        if self.is_gym(gym_postcode):
            raise custom_exceptions.GymExistsException(gym_postcode)
        
        super().add_record_to_table(self, table="gyms", gym_name=gym_name, gym_city=gym_city, postcode=gym_postcode)

    # Add a gym membership
    @cursor_handled(True)
    def add_user_gym_association(cursor: DictCursor, self, username: str, postcode: str):
        try:
            cursor.callproc("benjaminclough_COM6009M.add_users_gyms_record", [username, postcode])
            return {'state': 'successful'}
        except pymysql.err.IntegrityError as error:
            return {'state': 'membership already registered'}
        except pymysql.err.OperationalError as error:
            return {'state': error.args[1]}

    # Add a user workout
    def add_workout(self, workout_date: str, username: str, postcode: str) -> None:
        # Raise error if the workout already exists
        if self.is_workout(workout_date):
            raise custom_exceptions.WorkoutExistsException(workout_date)
        # Raise error if there is no user membership of a specific gym recorded
        user_gym_id = self.get_gym_user_id(self, username, postcode)['ID']
        if not user_gym_id:
            raise custom_exceptions.NoUserGymRelationException(username, postcode)
        # Add the record to the table
        super().add_record_to_table(self, table="workouts", workout_date=workout_date, users_gyms_id=user_gym_id)
        
    # Add multiple diary entries
    def add_diary_entries(self, *diary_entries: list[dict]) -> None:
        
        flattened_records = []
        for record in diary_entries:
            flattened_records.extend([record['exercise_ID'], record['weight_lifted'], record['repetitions'], record['workout_ID'], record['set_number']])
        
        if ['', 0] in flattened_records:
            raise custom_exceptions.MissingFieldException()
            
        insert_query = StatementGenerator.generate_multiple_record_insert_statement(
            'benjaminclough_COM6009M', 'diary_entries', len(diary_entries), 
            'exercise_ID', '`weight_lifted-kg`', 'repetitions', 'workout_ID', 'set_number')
        
        super().insert_statement(self, insert_query, flattened_records)

    # Add multiple exercises
    def add_exercises(self, *exercises):
        query = """INSERT INTO exercises (exercise) VALUES %s"""
        query = query % StatementGenerator.generate_multiple_record_VALUES_string(1, len(exercises))
        super().insert_statement(self, query, exercises)
        
    # Mark a user account as an admin
    def add_admin_account(self, user_ID: int, username: str):
        if self.is_admin(self, username):
            raise pymysql.err.IntegrityError()
            
        super().add_record_to_table(self, table="admin_users", users_ID=user_ID)
    
    # --- Record Exists Functionality --- #
    # Check for a user by the username
    def is_user(self, username: str) -> bool:
        return self.is_data_in_table_column(self, "users", "username", username)
    
    # Check for a gym by the address
    def is_gym(self, gym_address: str) -> bool:
        return self.is_data_in_table_column(self, "gyms", "postcode", gym_address)
    
    # Check for gym by the date, user, and gym
    def is_workout(self, workout_date: str) -> bool:
        # Check if the date-time format is valid
        if not is_valid_date(workout_date):
            raise custom_exceptions.InvalidDateTimeException(workout_date)
        
        # Create query
        return self.is_data_in_table_column(self, "workouts", "workout_date", workout_date)

    # Check if the user is an admin
    @cursor_handled()
    def is_admin(cursor: DictCursor, self, username: str) -> bool:
        query = """ SELECT EXISTS(
                        SELECT users.username
                        FROM users
                        RIGHT JOIN admin_users
                        ON users.ID = admin_users.users_ID 
                        WHERE users.username = %s
                        LIMIT 1) 
                    AS is_user_admin"""
        
        cursor.execute(query, username)
        record = cursor.fetchone()
        return bool(record['is_user_admin'])

    # --- Read Functionality --- #

    # Get a list of tables in the db
    def get_database_tables(self) -> list[dict]:
        returned_tables = super().get_tables()
        JSON_formatted = [{'table_name': record[0]} for record in returned_tables]
        return JSON_formatted
    
    # Get a total quantity of diary entries associated with a user
    def get_diary_entry_count(self, username: str) -> dict:
        query = """
                SELECT benjaminclough_COM6009M.get_user_total_diary_entry_count(%s) 
                AS diary_entry_count
                """
        
        result = super().single_select_statement(self, query, username)
        return result
        
    # Get a list of user workouts and the associated gym details
    def get_gym_workouts(self, username: str):
        query = """
                    SELECT workouts.ID as workout_ID, workouts.workout_date, gyms.gym_name, gym_city, gyms.postcode
                    FROM benjaminclough_COM6009M.workouts
                    INNER JOIN benjaminclough_COM6009M.`users-gyms`
                        ON workouts.users_gyms_ID = `users-gyms`.ID
                    INNER JOIN gyms
                        ON `users-gyms`.gym = gyms.ID
                    INNER JOIN users
                        ON `users-gyms`.user = users.ID
                    WHERE users.username = %s
                """
        records = super().select_statement(self, query, username)
        return records

    # Get the ID representing the gym that the user goes to
    @cursor_handled()
    def get_gym_user_id(cursor: DictCursor, self, username: str, gym_address) -> int:
        # Create query
        query = """
                    SELECT benjaminclough_COM6009M.`users-gyms`.ID
                    FROM `users-gyms`
                    INNER JOIN users ON `users-gyms`.user = users.ID
                    INNER JOIN gyms ON `users-gyms`.gym = gyms.ID
                    WHERE users.username = %s AND gyms.postcode = %s
                """
        
        # Execute query and retrieve record
        cursor.execute(query, [username, gym_address])
        record_retrieved = cursor.fetchone()

        # Return None to indicate no record found
        if not record_retrieved:
            return None
        
        return record_retrieved
    
    # Get gym memberships
    def get_gym_memberships(self, username: str):
        query = """ 
                    SELECT gyms.gym_name, gyms.postcode, gyms.gym_city, `users-gyms`.ID 
                    FROM benjaminclough_COM6009M.gyms
                    INNER JOIN benjaminclough_COM6009M.`users-gyms`
                        ON `users-gyms`.gym = gyms.ID
                    INNER JOIN benjaminclough_COM6009M.users
                        ON users.ID = `users-gyms`.user
                    WHERE username=%s
                """

        records = super().select_statement(self, query, username)
        return records

    # Get a user's record (ID, username, forename, surname)
    def get_user_record(self, username: str) -> dict:
        retrieved_result = super().single_column_record_select(self, 'users', 'username', username, 'ID', 'username', 'forename', 'surname')
        if not retrieved_result:
            return None

        return retrieved_result
	
    # Get the ID of a muscle group
    @cursor_handled()
    def get_muscle_group_id(cursor: DictCursor, self, muscle_group: str) -> int:

        # Create query
        query = """
                    SELECT ID
                    FROM benjaminclough_COM6009M.muscle_groups
                    WHERE muscle_group = %s
                """
        
        # Execute query
        
        cursor.execute(query, muscle_group)
        retrieved_id = cursor.fetchone()

        if not retrieved_id:
            return None
        
        return retrieved_id
    
    # Get a list of muscle groups
    def get_muscle_groups(self):
        query = "SELECT muscle_group from benjaminclough_COM6009M.muscle_groups"
        muscle_groups = super().select_statement(self, query)
        return muscle_groups

    # Get a hashed password from the database
    def get_password(self, username: str) -> dict:
        result = super().single_column_record_select(self, "users", "username", username, "password")
        return result
    
    # Get a list of exercises
    def get_exercises(self):
        result_list = []
        
        # Execute query
        query = """SELECT ID, exercise from benjaminclough_COM6009M.exercises"""
        result = super().select_statement(self, query)
            
        return result
    
    # Workout records associated with a gym membership
    def get_membership_workouts(self, username: str, gym_postcode: str) -> list[dict]:
        query = """
                SELECT workouts.workout_date, workouts.ID 
                FROM benjaminclough_COM6009M.workouts
                INNER JOIN benjaminclough_COM6009M.`users-gyms`
                    ON workouts.users_gyms_ID = `users-gyms`.ID
                INNER JOIN benjaminclough_COM6009M.gyms
                    ON `users-gyms`.gym = gyms.ID
                INNER JOIN benjaminclough_COM6009M.users
                    ON `users-gyms`.user = users.ID
                WHERE users.username = %s 
                    AND gyms.postcode = %s
                """
        workouts = super().select_statement(self, query, username, gym_postcode)
        return workouts
    
    # Get diary entry records associated with a workout
    def get_workout_diary_entries(self, username: str, gym_postcode: str, workout_date: str) -> list[dict]:
        query = """
                SELECT 
                    exercises.exercise, 
                    diary_entries.set_number, 
                    diary_entries.`weight_lifted-kg`, diary_entries.repetitions
                FROM benjaminclough_COM6009M.diary_entries
                INNER JOIN benjaminclough_COM6009M.exercises
                    ON diary_entries.exercise_ID = exercises.ID
                INNER JOIN benjaminclough_COM6009M.workouts
                    ON diary_entries.workout_ID = workouts.ID
                INNER JOIN benjaminclough_COM6009M.`users-gyms`
                    ON workouts.users_gyms_ID = `users-gyms`.ID
                INNER JOIN benjaminclough_COM6009M.users
                    ON `users-gyms`.user = users.ID
                INNER JOIN benjaminclough_COM6009M.gyms
                    ON `users-gyms`.gym = gyms.ID
                WHERE users.username = %s
                    AND gyms.postcode = %s
                    AND workouts.workout_date = %s
                """

        diary_entries = super().select_statement(self, query, username, gym_postcode, workout_date)
        return diary_entries
    
    # Return all diary entries associated with a user
    def get_all_user_diary_entries(self, username: int) -> list[dict]:
        query = """
                SELECT
                    diary_entries.ID,
                    diary_entries.set_number,
                    diary_entries.`weight_lifted-kg` AS weight_lifted,
                    diary_entries.repetitions,
                    exercises.exercise,
                    workouts.workout_date,
                    gyms.gym_name,
                    gyms.gym_city,
                    gyms.postcode
                FROM benjaminclough_COM6009M.diary_entries
                INNER JOIN benjaminclough_COM6009M.exercises
                    ON diary_entries.exercise_ID = exercises.ID
                INNER JOIN benjaminclough_COM6009M.workouts
                    ON diary_entries.workout_ID = workouts.ID
                INNER JOIN benjaminclough_COM6009M.`users-gyms`
                    ON workouts.users_gyms_ID = `users-gyms`.ID
                INNER JOIN benjaminclough_COM6009M.gyms
                    ON `users-gyms`.gym = gyms.ID
                INNER JOIN benjaminclough_COM6009M.users
                    ON `users-gyms`.user = users.ID
                WHERE users.username = %s
                GROUP BY 
                        gyms.gym_name,
                        gyms.gym_city,
                        gyms.postcode,  
                        workouts.workout_date, 
                        diary_entries.exercise_ID, 
                        diary_entries.set_number
                """
        diary_entries = super().select_statement(self, query, username)
        return diary_entries


    # Validate user credentials
    def credentials_valid(self, username: str, password: str) -> bool:
        
        # Get password from database
        db_password = self.get_password(username)['password']
        # Encode both passwords
        db_password_encoded = db_password.encode('utf-8')
        password_encoded = password.encode('utf-8')

        # Hash entered password
        hashed_password = bcrypt.hashpw(password_encoded, db_password_encoded)

        # Compare entered password to password in database
        return db_password_encoded == hashed_password

    # --- Update Functionality --- #

    # Update a user's account information
    def update_account_information(self, user_ID: int, **update_fields):
        super().single_record_update_statement(self, database_name=self.database_name, table_name='users', id_column_name='ID', record_ID=user_ID, **update_fields)

    # Update multiple diary entry records
    def update_multiple_diary_entries(self, *diary_entries: list[dict]):
        super().multiple_record_update_statement(self, self.database_name, 'diary_entries', 'ID', *diary_entries)

    # --- Delete Functionality --- #

    def remove_workout(self, workout_ID: int):
        super().single_record_delete(self, 'workouts', workout_ID)
        
    def delete_membership(self, user_gym_ID: int):
        super().single_record_delete(self, 'users-gyms', user_gym_ID)
        
    def delete_diary_entries(self, *diary_entry_IDs):
        super().multiple_record_delete(self, 'diary_entries', *diary_entry_IDs)
        
        
        
