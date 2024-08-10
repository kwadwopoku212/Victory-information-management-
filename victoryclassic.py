import streamlit as st
st.set_page_config(layout="wide")


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
                            timestamp TEXT NOT NULL,
                            attachment TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS email_history (
                            id INTEGER PRIMARY KEY,
                            recipient TEXT,
                            cc TEXT,
                            bcc TEXT,
                            subject TEXT,
                            message TEXT,
                            timestamp TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS user_permissions (
                            user_id INTEGER,
                            registration_access INTEGER,
                            payment_access INTEGER,
                            summary_access INTEGER,
                            chat_access INTEGER,
                            email_access INTEGER,
                            FOREIGN KEY (user_id) REFERENCES users (id))''')
        
        conn.commit()
    except sqlite3.Error as e:
        st.error("Error creating tables: " + str(e))

def alter_chat_table(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('ALTER TABLE chat ADD COLUMN attachment TEXT')
        conn.commit()
    except sqlite3.Error as e:
        if "duplicate column name" not in str(e):
            st.error("Error altering chat table: " + str(e))

# Authentication functions
def insert_user(conn, username, password, email, role, status="active"):
    cur = conn.cursor()
    sql = 'INSERT INTO users (username, password, email, role, status) VALUES (?, ?, ?, ?, ?)'
    cur.execute(sql, (username, hash_password(password), email, role, status))
    user_id = cur.lastrowid
    cur.execute('INSERT INTO user_permissions (user_id, registration_access, payment_access, summary_access, chat_access, email_access) VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, 1, 1, 1, 1, 1))  # By default, give full access
    conn.commit()

def check_credentials(conn, username, password):
    cur = conn.cursor()
    cur.execute('SELECT username, password, role, status FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    if user and verify_password(password, user[1]):
        return user[0], user[2], user[3]  # Returning username, role, and status
    return None, None, None

def fetch_all_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, status FROM users")
    rows = cur.fetchall()
    return rows

def fetch_user_permissions(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT registration_access, payment_access, summary_access, chat_access, email_access FROM user_permissions WHERE user_id = ?", (user_id,))
    return cur.fetchone()

def update_user_status(conn, user_id, status):
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
    conn.commit()

def update_user_permissions(conn, user_id, permissions):
    cur = conn.cursor()
    sql = '''UPDATE user_permissions
             SET registration_access=?, payment_access=?, summary_access=?, chat_access=?, email_access=?
             WHERE user_id=?'''
    cur.execute(sql, (*permissions, user_id))
    conn.commit()

def delete_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cur.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
    conn.commit()

# Student Registration Functions
def insert_registration_record(conn, record):
    sql = '''INSERT INTO student_registration(client_name, outstanding_document, assigned_to, application_date, institution_applied_to, status, decision, remarks, doc_file)
             VALUES(?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, record)
    conn.commit()

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

# Payment Functions
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

def fetch_payment_records_with_client_names(conn):
    cur = conn.cursor()
    cur.execute('''SELECT sp.id, sr.client_name, sp.student_registration_id, sp.requested_service, sp.quantity, sp.amount, sp.cost, sp.currency, sp.date
                   FROM student_payments sp
                   JOIN student_registration sr ON sp.student_registration_id = sr.id''')
    rows = cur.fetchall()
    return rows

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

# Chat Functions
def insert_chat_message(conn, user, message, attachment=None):
    sql = '''INSERT INTO chat(user, message, timestamp, attachment) VALUES(?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, (user, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), attachment))
    conn.commit()

def fetch_chat_messages(conn, contact):
    cur = conn.cursor()
    cur.execute("SELECT * FROM chat WHERE user=? ORDER BY timestamp DESC", (contact,))
    rows = cur.fetchall()
    return rows

def format_timestamp(timestamp):
    try:
        dt_object = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        return dt_object.strftime('%b %d, %Y %I:%M %p')
    except ValueError:
        return timestamp

# Email Functions
def send_email(recipient, cc, bcc, subject, message, attachments=[]):
    sender_email = "your_email@gmail.com"  # Replace with your email
    sender_password = "your_app_password"  # Replace with your app password

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Cc'] = cc
    msg['Bcc'] = bcc
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'html'))

    for attachment in attachments:
        msg.attach(attachment)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient.split(",") + cc.split(",") + bcc.split(","), text)
        server.quit()
        st.success(f"Email sent to {recipient} with subject '{subject}'")
    except Exception as e:
        st.error(f"Failed to send email: {str(e)}")

def insert_email_history(conn, recipient, cc, bcc, subject, message):
    sql = '''INSERT INTO email_history(recipient, cc, bcc, subject, message, timestamp)
             VALUES(?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, (recipient, cc, bcc, subject, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

def fetch_email_history(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM email_history ORDER BY timestamp DESC")
    rows = cur.fetchall()
    return rows

# Main Application Function
def main():
    st.title("Victory Information Management System")

    db_path = 'sika_manager.db'
    conn = create_connection(db_path)
    create_tables(conn)
    alter_chat_table(conn)  # Ensure the chat table has the 'attachment' column

    if conn.execute('SELECT * FROM users WHERE username = "admin"').fetchone() is None:
        insert_user(conn, 'admin', 'admin123', 'admin@example.com', 'admin')


# Initialize session state if not already done
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ""
    st.session_state['role'] = ""

# Login form
if not st.session_state['logged_in']:
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_button = st.button("Login")

    if login_button:
        user, role, status = check_credentials(conn, username, password)
        if user:
            if status == "suspended":
                st.error("Your account is suspended. Please contact the admin.")
            else:
                st.session_state['logged_in'] = True
                st.session_state['username'] = user
                st.session_state['role'] = role
                st.success(f"Welcome {user}!")
        else:
            st.error("Incorrect username or password")

# Logged in content
if st.session_state['logged_in']:
    st.sidebar.write(f"Logged in as: {st.session_state['username']} ({st.session_state['role']})")
    logout_button = st.sidebar.button("Logout")
    if logout_button:
        st.session_state['logged_in'] = False
        st.session_state['username'] = ""
        st.session_state['role'] = ""
            else:
                st.error("Incorrect username or password")
    else:
        st.sidebar.write(f"Logged in as: {st.session_state['username']} ({st.session_state['role']})")
        logout_button = st.sidebar.button("Logout")
        if logout_button:
            del st.session_state['username']
            del st.session_state['role']

        tab_titles = ["Student Registration", "Payments", "Summary & Visualization", "Chat", "Email"]
        if st.session_state['role'] == 'admin':
            tab_titles.append("Manage Users")

        tabs = st.tabs(tab_titles)

        # Student Registration Tab
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

        # Payments Tab
        with tabs[1]:
            st.header('Payments')
            student_ids = [row[0] for row in fetch_all_registration_records(conn)]
            if student_ids:
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

                st.subheader("Payment Records")
                payment_records = fetch_payment_records_with_client_names(conn)
                if payment_records:
                    columns = ['ID', 'Client Name', 'Student Registration ID', 'Requested Service', 'Quantity', 'Amount', 'Cost', 'Currency', 'Date']
                    df = pd.DataFrame(payment_records, columns=columns)
                    st.dataframe(df)

                    st.subheader("Edit/Delete Payment")
                    selected_payment_id = st.selectbox("Select Payment ID to Edit/Delete", df['ID'])
                    if st.button("Delete Payment"):
                        delete_payment_record(conn, selected_payment_id)
                        st.success("Payment deleted successfully!")

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

        # Summary & Visualization Tab
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

        # Chat Tab
        with tabs[3]:
            st.header('Chat')
            st.subheader('Send a Message')
            user = st.selectbox('User', [row[1] for row in fetch_all_users(conn)])
            message = st.text_area('Message')
            attachment = st.file_uploader("Attach a file", type=["jpg", "jpeg", "png", "pdf", "docx", "xlsx", "pptx"], accept_multiple_files=False)
            if st.button('Send'):
                attachment_path = None
                if attachment:
                    os.makedirs("uploads", exist_ok=True)
                    attachment_path = os.path.join("uploads", attachment.name)
                    with open(attachment_path, "wb") as f:
                        f.write(attachment.read())
                insert_chat_message(conn, user, message, attachment_path)

            st.subheader('Chat History')
            contact = st.selectbox("Select Contact", [row[1] for row in fetch_all_users(conn)])
            chat_messages = fetch_chat_messages(conn, contact)
            if chat_messages:
                for chat in chat_messages:
                    timestamp = format_timestamp(chat[3])
                    st.write(f"{timestamp} - {chat[1]}: {chat[2]}")
                    if chat[4]:
                        st.write(f"Attachment: {chat[4]}")
            refresh_rate = st.slider('Refresh rate (seconds)', 1, 30, 5)
            if st.button('Start Auto-Refresh'):
                time.sleep(refresh_rate)

        # Email Tab
        with tabs[4]:
            st.header("Send Email")
            with st.form("email_form"):
                recipient = st.text_input("Recipient Email")
                cc = st.text_input("CC")
                bcc = st.text_input("BCC")
                subject = st.text_input("Subject")
                email_message = st.text_area("Message")
                attachments = st.file_uploader("Attach files", type=["jpg", "jpeg", "png", "pdf", "docx", "xlsx", "pptx"], accept_multiple_files=True)
                send_email_button = st.form_submit_button("Send Email")

                if send_email_button:
                    attachment_files = []
                    for attachment in attachments:
                        part = MIMEText(attachment.read(), 'base64', 'utf-8')
                        part["Content-Disposition"] = f'attachment; filename="{attachment.name}"'
                        attachment_files.append(part)
                    send_email(recipient, cc, bcc, subject, email_message, attachment_files)
                    insert_email_history(conn, recipient, cc, bcc, subject, email_message)

            st.subheader('Email History')
            email_history = fetch_email_history(conn)
            if email_history:
                for email in email_history:
                    timestamp = format_timestamp(email[6])
                    st.write(f"{timestamp} - To: {email[1]}, CC: {email[2]}, BCC: {email[3]}, Subject: {email[4]}, Message: {email[5]}")

        # Manage Users Tab (Admin only)
        if st.session_state['role'] == 'admin':
            with tabs[5]:
                st.header("Manage Users")
                
                # Create New User
                with st.form("user_management_form"):
                    new_username = st.text_input("New Username")
                    new_password = st.text_input("New Password", type="password")
                    new_email = st.text_input("Email Address")
                    new_role = st.selectbox("Role", ["admin", "worker"])
                    add_user_button = st.form_submit_button(label="Add User")

                    if add_user_button:
                        try:
                            insert_user(conn, new_username, new_password, new_email, new_role)
                            st.success("New user added successfully!")
                        except sqlite3.IntegrityError:
                            st.error("Username already exists!")

                # Display User List
                st.subheader("User List")
                user_records = fetch_all_users(conn)
                if user_records:
                    columns = ['ID', 'Username', 'Email', 'Role', 'Status']
                    df = pd.DataFrame(user_records, columns=columns)
                    st.dataframe(df)

                    selected_user_id = st.selectbox("Select User ID to Edit/Delete/Suspend", df['ID'])

                    if selected_user_id:
                        selected_user = df[df['ID'] == selected_user_id].iloc[0]
                        
                        # Suspend User
                        if st.button(f"Suspend {selected_user['Username']}"):
                            update_user_status(conn, selected_user_id, "suspended")
                            st.success(f"User {selected_user['Username']} suspended.")

                        # Reactivate User
                        if st.button(f"Reactivate {selected_user['Username']}"):
                            update_user_status(conn, selected_user_id, "active")
                            st.success(f"User {selected_user['Username']} reactivated.")

                        # Delete User
                        if st.button(f"Delete {selected_user['Username']}"):
                            delete_user(conn, selected_user_id)
                            st.success(f"User {selected_user['Username']} deleted.")

                        # Update User Permissions
                        st.subheader("Update User Permissions")
                        user_permissions = fetch_user_permissions(conn, selected_user_id)
                        if user_permissions:
                            registration_access = st.checkbox("Access Registration", value=user_permissions[0])
                            payment_access = st.checkbox("Access Payments", value=user_permissions[1])
                            summary_access = st.checkbox("Access Summary", value=user_permissions[2])
                            chat_access = st.checkbox("Access Chat", value=user_permissions[3])
                            email_access = st.checkbox("Access Email", value=user_permissions[4])

                            if st.button("Update Permissions"):
                                permissions = (registration_access, payment_access, summary_access, chat_access, email_access)
                                update_user_permissions(conn, selected_user_id, permissions)
                                st.success("Permissions updated successfully!")

if __name__ == '__main__':
    main()
