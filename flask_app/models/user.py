from flask_app.config.mysqlconnection import MySQLConnection
from flask import flash
from flask_app import app
from flask_bcrypt import Bcrypt
import re
CHAR_REGEX = re.compile(r'^[a-zA-Z]')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
bcrypt = Bcrypt(app)

class User:
    DB = 'login_and_registration_schema'
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def register_user(cls, data):
        query = """
        INSERT INTO users(first_name, last_name, email, password)
        VALUES(%(first_name)s, %(last_name)s, %(email)s, %(password)s)
        """
        return MySQLConnection(cls.DB).query_db(query,data)

    @classmethod
    def get_by_email(cls, data):
        query = 'SELECT * FROM users WHERE email = %(email)s;'
        result = MySQLConnection(cls.DB).query_db(query,data)
        if len(result) < 1:
            return False
        else:
            return cls(result[0])

    @classmethod
    def user_logged_in(cls, data):
        query = 'SELECT * FROM users WHERE id = %(id)s;'
        result = MySQLConnection(cls.DB).query_db(query,data)
        return cls(result[0])

    @classmethod
    def unique_email(cls,data):
        query = """
        SELECT email FROM users
        """
        result = MySQLConnection(cls.DB).query_db(query)
        emails = []
        for email in result:
            emails.append(email)
        for email in emails:
            if email['email'] == data:
                flash('Email in use', 'register')
                return True
        return result

    @staticmethod
    def user_vald_register(input):
        is_valid = True
        if not input['first_name'] and not input['last_name'] and not input['email'] and not input['password'] and not input['confirm_password']:
            flash('All fields required', 'register')
            is_valid = False
        if len(input['first_name']) < 2:
            flash('First Name must be at least 2 characters', 'register')
            is_valid = False
        if not CHAR_REGEX.match(input['first_name']):
            flash('First Name must be alphabetic letters', 'register')
            is_valid = False

        if len(input['last_name']) < 2:
            flash('Last Name must be at least 2 characters', 'register')
            is_valid = False
        if not CHAR_REGEX.match(input['last_name']):
            flash('Last Name must be alphabetic letters', 'register')
            is_valid = False
        
        if not EMAIL_REGEX.match(input['email']):
            flash('Email is not valid', 'register')
            is_valid = False

        if len(input['password']) < 8:
            flash('Password must be at least 8 characters', 'register')
            is_valid = False
        return is_valid