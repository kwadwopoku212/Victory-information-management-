
import sqlite3
import streamlit as st
from passlib.hash import pbkdf2_sha256
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Utility functions
def hash_password(password):
    return pbkdf2_sha256.hash(password)

def verify_password(password, hashed):
    return pbkdf2_sha256.verify(password, hashed)

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
    except sqlite3.Error as e:
        st.error("Error connecting to database: " + str(e))
    return conn

def create_tables(conn):
    try:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            email TEXT DEFAULT '',
                            role TEXT NOT NULL,
                            status TEXT DEFAULT 'active')''')

        # Create other necessary tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS student_registration (
                            id INTEGER PRIMARY KEY,
                            client_name TEXT NOT NULL,
                            outstanding_document TEXT,
                            assigned_to TEXT,
                            application_date TEXT,
                            institution_applied_to TEXT,
                            status TEXT,
                            decision TEXT,
                            remarks TEXT,
                            doc_file BLOB)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS student_payments (
                            id INTEGER PRIMARY KEY,
                            student_registration_id INTEGER,
                            requested_services TEXT,
                            payment_date TEXT,
                            amount_paid REAL,
                            FOREIGN KEY (student_registration_id) REFERENCES student_registration (id))''')

        conn.commit()
    except sqlite3.Error as e:
        st.error("Error creating tables: " + str(e))

# New functions to handle roles and permissions
def get_user_role_and_status(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT role, status FROM users WHERE username=?", (username,))
    return cursor.fetchone()

def is_user_authorized(conn, username, required_role):
    role, status = get_user_role_and_status(conn, username)
    if status != 'active':
        st.warning("Your account is currently suspended.")
        return False
    if role != required_role:
        st.warning(f"Unauthorized: {required_role} access required.")
        return False
    return True

# Example usage within the app
def some_sensitive_function(conn, username):
    if not is_user_authorized(conn, username, 'admin'):
        return
    # Proceed with the sensitive function

# Example usage for regular users
def some_user_function(conn, username):
    if not is_user_authorized(conn, username, 'user'):
        return
    # Proceed with the regular user function

# Main app logic
def main():
    conn = create_connection('your_database.db')
    create_tables(conn)
    
    # Assuming the login logic sets the logged-in username
    username = "some_username"  # This should be dynamically set during login
    
    # Check access and proceed based on role
    some_sensitive_function(conn, username)
    some_user_function(conn, username)

if __name__ == "__main__":
    main()
