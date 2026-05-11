# Database connection setup using mysql.connector
import mysql.connector

# Database connection parameters
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="nishit",
        database="smart_campus_security"
    )
    cursor = db.cursor(dictionary=True)
    print("Database connection successful")

# Handle connection errors
except mysql.connector.Error as err:
    print(f"Error connecting to database: {err}")