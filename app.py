from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import db,cursor

app = Flask(__name__)
app.secret_key = "smaetcampus"

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/create-admin', methods=['GET', 'POST'])
def create_admin():
    secret_key = "supersecret123"   # you can change this

    if request.method == 'POST':
        key = request.form['key']

        if key != secret_key:
            return "Unauthorized Access ❌"

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        query = "INSERT INTO USER (username,email,password,role) VALUES (%s,%s,%s,%s)"
        values = (username, email, hashed_password, "admin")

        cursor.execute(query, values)
        db.commit()

        return render_template("create_admin.html", success="Admin created successfully! Redirecting to login...")

    return render_template('create_admin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password,method='pbkdf2:sha256')
        role = 'user'  # Default role is 'user'
        
        query = "INSERT INTO USER (username,email,password,role) VALUES (%s,%s,%s,%s)"
        values = (username,email,hashed_password,role)

        cursor.execute(query, values)
        db.commit()

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Get user by username only
        query = "SELECT * FROM USER WHERE username=%s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        # Check hashed password
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']

            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/admin')
def admin_dashboard():
    if session.get('role') == 'admin':

        cursor.execute("SELECT * FROM assets")
        assets = cursor.fetchall()

        return render_template('admin.html', assets=assets)
    return redirect(url_for('login'))

@app.route('/user')
def user_dashboard():
    if session.get('role') in ['user', 'admin']:
        cursor.execute("SELECT * FROM assets")
        assets = cursor.fetchall()
        return render_template('user.html', assets=assets)
    return redirect(url_for('login'))

@app.route('/add_asset', methods=['GET', 'POST'])
def add_asset():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        device_name = request.form['device_name']
        device_type = request.form['device_type']
        ip_address = request.form['ip_address']
        mac_address = request.form['mac_address']
        location = request.form['location']
        status = request.form['status']

        query = """
        INSERT INTO assets (device_name, device_type, ip_address, mac_address, location, status)
        VALUES (%s,%s,%s,%s,%s,%s)
        """

        cursor.execute(query,(device_name,device_type,ip_address,mac_address,location,status))
        db.commit()

        return redirect(url_for('admin_dashboard'))
    return render_template('add_devices.html')

@app.route('/delete/<int:asset_id>')
def delete_asset(asset_id):
    if session.get('role') == 'admin':
        return redirect(url_for('login'))
    cursor.execute("DELETE FROM assets WHERE id=%s", (asset_id,))
    db.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/edit/<int:asset_id>', methods=['GET', 'POST'])
def edit_asset(asset_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Fetch asset from DB
    cursor.execute("SELECT * FROM assets WHERE id=%s", (asset_id,))
    asset = cursor.fetchone()

    if not asset:
        return "Asset not found", 404

    if request.method == 'POST':
        device_name = request.form['device_name']
        device_type = request.form['device_type']
        ip_address = request.form['ip_address']
        mac_address = request.form['mac_address']
        location = request.form['location']
        status = request.form['status']

        query = """
        UPDATE assets 
        SET device_name=%s,
            device_type=%s,
            ip_address=%s,
            mac_address=%s,
            location=%s,
            status=%s
        WHERE id=%s
        """

        cursor.execute(query, (
            device_name,
            device_type,
            ip_address,
            mac_address,
            location,
            status,
            asset_id
        ))

        db.commit()

    return redirect(url_for('admin_dashboard'))

@app.route('/report')
def report_page():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    cursor.execute("SELECT * FROM assets")
    assets = cursor.fetchall()
    return render_template('report_page.html', assets=assets)

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']

        query="SELECT * FROM user WHERE username=%s"
        cursor.execute(query,(username,))
        user = cursor.fetchone()

        return render_template(
            'profile.html',
            username=username,
            email=user.get('email'),
            role=user.get('role')
        )

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)