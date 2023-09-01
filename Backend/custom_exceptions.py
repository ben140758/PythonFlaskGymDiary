class MissingFieldException(ValueError):
    """Used when a required field for a query is missing"""
    def __init__(self):
        super().__init__("Missing Field")

class DataNotFoundException(Exception):
    def __init__(self, table: str, column: str, error_msg: str=None, *data: object):
        if error_msg:
            super().__init__(error_msg % (table, column, *data,))
        else:
            super().__init__(f"'{data}' not found in {table}.{column}")

class UserNotFoundException(DataNotFoundException):
    """Used when a user is not found in a database"""

    def __init__(self, username: str):
        super().__init__("users", "username", data=username)

class GymNotFoundException(DataNotFoundException):
    """Used when a gym is not found in a database"""

    def __init__(self, postcode: str):
        super().__init__("gyms", "postcode", error_msg="Gym at address '%s' not found in %s.%s", data=postcode)

class NoUserGymRelationException(DataNotFoundException):
    """Used when the provided users-gyms ID does not exist in the database"""

    def __init__(self, username: str, postcode: str):
        super().__init__("users-gyms", "ID", "In %s.%s, No user membership found with Gym, User: '%s', Gym Postcode: '%s'", *[username, postcode])

class MuscleGroupNotFoundException(DataNotFoundException):
    """Used when the provided muscle group does not exist in the database"""

    def __init__(self, muscle_group: str):
        super().__init__("muscle_groups", "muscle_group", data=muscle_group)

class DataExistsException(Exception):
    def __init__(self, table: str, column: str, data: object):
        super().__init__(f"'{data}' already exists in {table}.{column}")

class UserExistsException(DataExistsException):
    """Used when a user is found in a database when trying to insert a duplicate"""

    def __init__(self, username: str):
        super().__init__("users", "username", username)

class ExerciseExistsException(DataExistsException):
    """Used when an exercise is found in a database when trying to insert a duplicate"""

    def __init__(self, exercise: str):
        super().__init__("exercises", "exercise", exercise)

class GymExistsException(DataExistsException):
    """Used when a gym is found in a database when trying to insert a duplicate"""

    def __init__(self, postcode: str):
        super().__init__("gyms", "postcode", postcode)

class WorkoutExistsException(DataExistsException):
    """Used when a workout is found in a database when trying to insert a duplicate"""

    def __init__(self, workout_date: str):
        super().__init__("workouts", "workout_date", workout_date.split('T')[0])

class InvalidDateTimeException(Exception):
    """Used when validating datetime strings"""

    def __init__(self, datetime: str):
        super().__init__(f"datetime '{datetime}' invalid for ISO format")