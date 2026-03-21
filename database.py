import mysql.connector
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="nishit",
        database="smart_campus_security"
    )
    cursor = db.cursor(dictionary=True)
    print("Database connection successful")

except mysql.connector.Error as err:
    print(f"Error connecting to database: {err}")