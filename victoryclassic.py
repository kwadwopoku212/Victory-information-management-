import sqlite3
import streamlit as st
from passlib.hash import pbkdf2_sha256
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time

# Function to trigger rerun
def trigger_rerun():
    st.session_state['rerun_trigger'] = not st.session_state.get('rerun_trigger', False)
    time.sleep(1)

# Database connection function
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
    except sqlite3.Error as e:
        st.error("Error connecting to database: " + str(e))
    return conn

# Create necessary tables
def create_tables(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            role TEXT NOT NULL)''')
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
                            requested_service TEXT,
                            quantity INTEGER,
                            amount REAL,
                            cost REAL,
                            currency TEXT,
                            date TEXT,
                            balance_due REAL,
                            FOREIGN KEY (student_registration_id) REFERENCES student_registration (id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS chat (
                            id INTEGER PRIMARY KEY,
                            user TEXT NOT NULL,
                            message TEXT NOT NULL,
                            timestamp TEXT NOT NULL)''')
        conn.commit()
    except sqlite3.Error as e:
        st.error("Error creating tables: " + str(e))

# Alter tables to add new columns if needed
def alter_table(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('ALTER TABLE student_payments ADD COLUMN balance_due REAL')
        conn.commit()
    except sqlite3.Error as e:
        if "duplicate column name" not in str(e):
            st.error("Error altering table: " + str(e))

# Authentication functions
def hash_password(password):
    return pbkdf2_sha256.hash(password)

def verify_password(password, hashed):
    return pbkdf2_sha256.verify(password, hashed)

def insert_user(conn, username, password, role):
    cur = conn.cursor()
    sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)'
    cur.execute(sql, (username, hash_password(password), role))
    conn.commit()

def check_credentials(conn, username, password):
    cur = conn.cursor()
    cur.execute('SELECT username, password, role FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    if user and verify_password(password, user[1]):
        return user[0], user[2]
    return None, None

def fetch_all_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users")
    rows = cur.fetchall()
    return rows

# Chat functions
def insert_chat_message(conn, user, message):
    sql = '''INSERT INTO chat(user, message, timestamp) VALUES(?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, (user, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

def fetch_chat_messages(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat ORDER BY timestamp DESC")
    rows = cur.fetchall()
    return rows

# Payment and registration functions
def insert_registration_record(conn, record):
    sql = '''INSERT INTO student_registration(client_name, outstanding_document, assigned_to, application_date, institution_applied_to, status, decision, remarks, doc_file)
             VALUES(?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, record)
    conn.commit()

def insert_payment_record(conn, record):
    sql = '''INSERT INTO student_payments(student_registration_id, requested_service, quantity, amount, cost, currency, date, balance_due)
             VALUES(?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, record)
    conn.commit()

def fetch_all_payment_records(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM student_payments")
    rows = cur.fetchall()
    return rows

def fetch_all_registration_records(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, client_name, outstanding_document, assigned_to, application_date, institution_applied_to, status, decision, remarks FROM student_registration")
    rows = cur.fetchall()
    return rows

def update_registration_record(conn, record):
    sql = '''UPDATE student_registration
             SET client_name=?, outstanding_document=?, assigned_to=?, application_date=?, institution_applied_to=?, status=?, decision=?, remarks=?
             WHERE id=?'''
    cur = conn.cursor()
    cur.execute(sql, record)
    conn.commit()

def delete_registration_record(conn, record_id):
    sql = '''DELETE FROM student_registration WHERE id=?'''
    cur = conn.cursor()
    cur.execute(sql, (record_id,))
    conn.commit()

def update_payment_record(conn, record):
    sql = '''UPDATE student_payments
             SET student_registration_id=?, requested_service=?, quantity=?, amount=?, cost=?, currency=?, date=?, balance_due=?
             WHERE id=?'''
    cur = conn.cursor()
    cur.execute(sql, record)
    conn.commit()

def delete_payment_record(conn, record_id):
    sql = '''DELETE FROM student_payments WHERE id=?'''
    cur = conn.cursor()
    cur.execute(sql, (record_id,))
    conn.commit()

# Email function
def send_email(to, subject, message):
    sender_email = "your_email@gmail.com"  # Replace with your email
    sender_password = "your_app_password"  # Replace with your app password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, to, text)
        server.quit()
        st.success(f"Email sent to {to} with subject '{subject}' and message '{message}'")
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")

# Main Streamlit application
def main():
    st.title("SIKA Manager")

    # Database connection
    db_path = 'sika_manager.db'
    conn = create_connection(db_path)
    create_tables(conn)
    alter_table(conn)

    # Default admin user (only runs once)
    if conn.execute('SELECT * FROM users WHERE username = "admin"').fetchone() is None:
        insert_user(conn, 'admin', 'admin123', 'admin')

    # Sidebar for login
    if 'username' not in st.session_state:
        st.sidebar.title("Login")
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        login_button = st.sidebar.button("Login")

        if login_button:
            user, role = check_credentials(conn, username, password)
            if user:
                st.session_state['username'] = user
                st.session_state['role'] = role
                st.success(f"Welcome {user}!")
                trigger_rerun()
            else:
                st.error("Incorrect username or password")
    else:
        st.sidebar.write(f"Logged in as: {st.session_state['username']} ({st.session_state['role']})")
        logout_button = st.sidebar.button("Logout")
        if logout_button:
            del st.session_state['username']
            del st.session_state['role']
            trigger_rerun()

        tab_titles = ["Student Registration", "Payments", "Summary & Visualization", "Chat", "Email"]
        if st.session_state['role'] == 'admin':
            tab_titles.append("Manage Users")

        tabs = st.tabs(tab_titles)

        with tabs[0]:
            st.header("Student Registration")
            with st.form("student_registration_form"):
                client_name = st.text_input("Client Name")
                outstanding_document = st.text_input("Outstanding Document")
                assigned_to = st.text_input("Assigned To")
                application_date = st.date_input("Application Date")
                institution_applied_to = st.text_input("Institution Applied To")
                status = st.selectbox("Status", ["In Process", "Pending Review", "Submitted"])
                decision = st.selectbox("Decision", ["Successful", "Conditional", "Unsuccessful"])
                remarks = st.text_area("Remarks")
                doc_file = st.file_uploader("Upload Document", type=["pdf", "docx", "jpg", "png"])
                submit_button = st.form_submit_button(label="Register")

                if submit_button:
                    doc_file_content = doc_file.read() if doc_file is not None else None
                    record = (client_name, outstanding_document, assigned_to, application_date.strftime('%Y-%m-%d'), institution_applied_to, status, decision, remarks, doc_file_content)
                    insert_registration_record(conn, record)
                    st.success("Student registered successfully!")
                    trigger_rerun()

            st.subheader("Registered Students")
            records = fetch_all_registration_records(conn)
            if records:
                columns = ['ID', 'Client Name', 'Outstanding Document', 'Assigned To', 'Application Date', 'Institution Applied To', 'Status', 'Decision', 'Remarks']
                df = pd.DataFrame(records, columns=columns)
                st.dataframe(df)

                st.subheader("Edit/Delete Record")
                selected_id = st.selectbox("Select ID to Edit/Delete", df['ID'])
                if st.button("Delete Record"):
                    delete_registration_record(conn, selected_id)
                    st.success("Record deleted successfully!")
                    trigger_rerun()

                if st.button("Edit Record"):
                    record = df[df['ID'] == selected_id].iloc[0]
                    with st.form(f"edit_form_{selected_id}"):
                        client_name = st.text_input("Client Name", value=record['Client Name'])
                        outstanding_document = st.text_input("Outstanding Document", value=record['Outstanding Document'])
                        assigned_to = st.text_input("Assigned To", value=record['Assigned To'])
                        application_date = st.date_input("Application Date", value=datetime.strptime(record['Application Date'], '%Y-%m-%d'))
                        institution_applied_to = st.text_input("Institution Applied To", value=record['Institution Applied To'])
                        status = st.selectbox("Status", ["In Process", "Pending Review", "Submitted"], index=["In Process", "Pending Review", "Submitted"].index(record['Status']))
                        decision = st.selectbox("Decision", ["Successful", "Conditional", "Unsuccessful"], index=["Successful", "Conditional", "Unsuccessful"].index(record['Decision']))
                        remarks = st.text_area("Remarks", value=record['Remarks'])
                        submit_edit = st.form_submit_button(label="Update Record")

                        if submit_edit:
                            update_registration_record(conn, (client_name, outstanding_document, assigned_to, application_date.strftime('%Y-%m-%d'), institution_applied_to, status, decision, remarks, selected_id))
                            st.success("Record updated successfully!")
                            trigger_rerun()

        with tabs[1]:
            st.header('Payments')
            student_ids = [row[0] for row in fetch_all_registration_records(conn)]
            selected_id = st.selectbox('Select Student Registration ID to Add Payment', student_ids)
            if selected_id:
                with st.form("payment_form"):
                    requested_service = st.text_input("Requested Service")
                    quantity = st.number_input("Quantity", min_value=1, step=1)
                    amount = st.number_input("Amount", min_value=0.0, step=0.01)
                    cost = st.number_input("Cost", min_value=0.0, step=0.01)
                    currency = st.selectbox("Currency", ["Ghc", "USD", "EUR", "GBP"])
                    date = st.date_input("Date")
                    balance_due = st.number_input("Balance Due", min_value=0.0, step=0.01)
                    submit_payment = st.form_submit_button(label="Add Payment Record")

                    if submit_payment:
                        payment_record = (selected_id, requested_service, quantity, amount, cost, currency, date.strftime('%Y-%m-%d'), balance_due)
                        insert_payment_record(conn, payment_record)
                        st.success("Payment record added successfully!")
                        trigger_rerun()

            st.subheader("Payment Records")
            payment_records = fetch_all_payment_records(conn)
            if payment_records:
                columns = ['ID', 'Student Registration ID', 'Requested Service', 'Quantity', 'Amount', 'Cost', 'Currency', 'Date', 'Balance Due']
                df = pd.DataFrame(payment_records, columns=columns)
                st.dataframe(df)

                st.subheader("Edit/Delete Payment")
                selected_payment_id = st.selectbox("Select Payment ID to Edit/Delete", df['ID'])
                if st.button("Delete Payment"):
                    delete_payment_record(conn, selected_payment_id)
                    st.success("Payment deleted successfully!")
                    trigger_rerun()

                if st.button("Edit Payment"):
                    payment = df[df['ID'] == selected_payment_id].iloc[0]
                    with st.form(f"edit_payment_form_{selected_payment_id}"):
                        student_registration_id = st.selectbox('Select Student Registration ID', student_ids, index=student_ids.index(payment['Student Registration ID']))
                        requested_service = st.text_input("Requested Service", value=payment['Requested Service'])
                        quantity = st.number_input("Quantity", min_value=1, step=1, value=payment['Quantity'])
                        amount = st.number_input("Amount", min_value=0.0, step=0.01, value=payment['Amount'])
                        cost = st.number_input("Cost", min_value=0.0, step=0.01, value=payment['Cost'])
                        currency = st.selectbox("Currency", ["Ghc", "USD", "EUR", "GBP"], index=["Ghc", "USD", "EUR", "GBP"].index(payment['Currency']))
                        date = st.date_input("Date", value=datetime.strptime(payment['Date'], '%Y-%m-%d'))
                        balance_due = st.number_input("Balance Due", min_value=0.0, step=0.01, value=payment['Balance Due'])
                        submit_edit = st.form_submit_button(label="Update Payment Record")

                        if submit_edit:
                            update_payment_record(conn, (student_registration_id, requested_service, quantity, amount, cost, currency, date.strftime('%Y-%m-%d'), balance_due, selected_payment_id))
                            st.success("Payment record updated successfully!")
                            trigger_rerun()

        with tabs[2]:
            st.header('Summary Statistics and Visualization')
            summary_statistics = conn.execute("SELECT currency, SUM(amount), SUM(balance_due) FROM student_payments GROUP BY currency").fetchall()
            if summary_statistics:
                df = pd.DataFrame(summary_statistics, columns=["Currency", "Total Amount", "Total Balance Due"])
                st.table(df)

                currency_data = df["Currency"]
                amount_data = df["Total Amount"]

                fig, ax = plt.subplots()
                ax.bar(currency_data, amount_data)
                st.pyplot(fig)

        with tabs[3]:
            st.header('Chat')
            st.subheader('Send a Message')
            user = st.selectbox('User', [row[0] for row in fetch_all_users(conn)])
            message = st.text_area('Message')
            if st.button('Send'):
                insert_chat_message(conn, user, message)
                trigger_rerun()

            st.subheader('Chat Messages')
            chat_messages = fetch_chat_messages(conn)
            for chat in chat_messages:
                st.write(f"{chat[3]} - {chat[1]}: {chat[2]}")

        with tabs[4]:
            st.header("Send Email")
            with st.form("email_form"):
                recipient = st.text_input("Recipient Email")
                subject = st.text_input("Subject")
                email_message = st.text_area("Message")
                send_email_button = st.form_submit_button("Send Email")

                if send_email_button:
                    send_email(recipient, subject, email_message)

        if st.session_state['role'] == 'admin':
            with tabs[5]:
                st.header("Manage Users")
                with st.form("user_management_form"):
                    new_username = st.text_input("New Username")
                    new_password = st.text_input("New Password", type="password")
                    new_role = st.selectbox("Role", ["admin", "worker"])
                    add_user_button = st.form_submit_button(label="Add User")

                    if add_user_button:
                        try:
                            insert_user(conn, new_username, new_password, new_role)
                            st.success("New user added successfully!")
                            trigger_rerun()
                        except sqlite3.IntegrityError:
                            st.error("Username already exists!")

                st.subheader("User List")
                user_records = fetch_all_users(conn)
                if user_records:
                    columns = ['Username', 'Role']
                    df = pd.DataFrame(user_records, columns=columns)
                    st.dataframe(df)

if __name__ == '__main__':
    main()
