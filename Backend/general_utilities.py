import datetime
from flaskext.mysql import MySQL
import jwt

# Taken from https://stackoverflow.com/questions/16870663/how-do-i-validate-a-date-string-format-in-python
def is_valid_date(date: str) -> bool:
    try:
        datetime.date.fromisoformat(date.split('T')[0])
        return True
    except ValueError:
        return False
    
# Generate a JWT access token
def generate_token(username: str, secret_key: str):
    token=jwt.encode(payload={  'user' : username, 
                                'exp' : datetime.datetime.utcnow()+datetime.timedelta(minutes=60)}, 
                     key=secret_key, 
                     algorithm='HS256')
    return token
