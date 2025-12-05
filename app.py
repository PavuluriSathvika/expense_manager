from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime
from flask_mail import Mail, Message
from stoken import endata, dedata
import mysql.connector
import random
import re
import string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "1234"

# ---------- DATABASE CONFIG ----------
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="admin",  # <-- change this to your MySQL password
    database="expense_manager"
)
# ---------- MAIL CONFIG ----------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pavulurisathvika533@gmail.com'
app.config['MAIL_PASSWORD'] = 'suht teyc mrln tqjx'  # use app password (not Gmail password)
app.config['MAIL_DEFAULT_SENDER'] = ('Expense Manager', 'pavulurisathvika533@gmail.com')
mail = Mail(app)

# ---------- THEME ROUTE ----------
@app.route('/set_theme/<theme>')
def set_theme(theme):
    if theme in ['light', 'dark']:
        session['theme'] = theme
    return redirect(request.referrer or url_for('dashboard'))

# ---------- REGISTER ----------
@app.route('/', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    theme = session.get('theme', 'dark')  # default dark
    if request.method == 'POST':
        username = request.form['username']
        usermail = request.form['email']
        password = request.form['password']

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(pattern, password):
            flash("Password must contain at least 8 characters including uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for('register'))

        cur = mydb.cursor()
        cur.execute("SELECT * FROM users WHERE usermail=%s", [usermail])
        user = cur.fetchone()
        if user:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for('login'))

        otp = ''.join(random.choices(string.digits, k=6))
        session['temp_user'] = {
            'username': username,
            'usermail': usermail,
            'password': password,
            'otp': otp
        }

        msg = Message('Expense Manager - OTP Verification',
                      sender='pavulurisathvika533@gmail.com',
                      recipients=[usermail])
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)

        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for('verify_otp'))

    return render_template('register.html', theme=theme)

# ---------- OTP VERIFY ----------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    theme = session.get('theme', 'dark')
    if request.method == 'POST':
        entered_otp = request.form['otp']
        temp_user = session.get('temp_user')
        if temp_user and entered_otp == temp_user['otp']:
            hashed_pw = generate_password_hash(temp_user['password'])
            cur = mydb.cursor()
            cur.execute("INSERT INTO users(username, usermail, password) VALUES(%s, %s, %s)",
                        (temp_user['username'], temp_user['usermail'], hashed_pw))
            mydb.commit()
            cur.close()

            session.pop('temp_user', None)
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        else:
            flash("Entered wrong OTP!", "danger")
            return redirect(url_for('verify_otp'))
    return render_template('otp_verify.html', theme=theme)

# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    theme = session.get('theme', 'dark')
    if request.method == 'POST':
        login_input = request.form['username']
        password = request.form['password']

        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s OR usermail = %s", (login_input, login_input))
        user = cursor.fetchone()

        if user:
            if check_password_hash(user['password'], password):
                session['username'] = user['username']
                session['user_id'] = user['id']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('No account found with that username or email.', 'danger')

        return redirect(url_for('login'))

    return render_template('login.html', theme=theme)

@app.route('/logout')
def logout():
    lang = session.get('lang', 'en')
    session.clear()
    session['lang'] = lang
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# ---------- DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')

    username = session['username']
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor()

    cursor.execute("SELECT id, salary FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    user_id = user[0]
    monthly_salary = float(user[1]) if user[1] else 0.0

    cursor.execute("SELECT SUM(amount) FROM expenses WHERE user_id=%s", (user_id,))
    total_spent = float(cursor.fetchone()[0] or 0.0)

    cursor.execute("SELECT SUM(saved_amount) FROM savings_goals WHERE user_id=%s", (user_id,))
    total_saved = float(cursor.fetchone()[0] or 0.0)

    remaining = monthly_salary - total_spent - total_saved
  

# ---------- Prevent negative remaining + trigger JS popup ----------
    

    show_popup = remaining < 0
    if remaining < 0:
        remaining = 0


    




    cursor.execute("""
        SELECT category, SUM(amount)
        FROM expenses
        WHERE user_id=%s
        GROUP BY category
    """, (user_id,))
    results = cursor.fetchall()
    if results:
        categories = [r[0] for r in results]
        category_amounts = [float(r[1]) for r in results]
        top_category = max(results, key=lambda x: float(x[1]))
        top_expense_category = top_category[0]
        top_expense_value = float(top_category[1])
    else:
        categories = []
        category_amounts = []
        top_expense_category = "None"
        top_expense_value = 0.0

    saving_rate = (total_saved / monthly_salary * 100) if monthly_salary else 0
    if saving_rate < 20:
        suggestion = "💡 Try reducing entertainment or shopping expenses to improve savings."
    elif saving_rate < 40:
        suggestion = "✅ You’re doing well! A small cut in food or travel can boost savings."
    else:
        suggestion = "🌟 Excellent savings discipline! Keep up your budget tracking."

    insights = [
        f"📊 Your top spending category is {top_expense_category} (₹{top_expense_value:.2f}).",
        f"💰 You saved {saving_rate:.1f}% of your monthly income.",
        suggestion
    ]

    mydb_conn.close()

    return render_template(
    'dashboard.html',
    theme=theme,
    total_spent=total_spent,
    monthly_salary=monthly_salary,
    total_saved=total_saved,
    remaining=remaining,
    categories=categories,
    category_amounts=category_amounts,
    insights=insights,
    show_popup=show_popup  
)


# ---------- MONTHLY SALARY ----------
@app.route('/monthly_salary', methods=['GET', 'POST'])
def monthly_salary():
    if 'username' not in session:
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')

    username = session['username']
    cursor = mydb.cursor()
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()[0]

    if request.method == 'POST':
        salary = request.form['salary']
        cursor.execute("UPDATE users SET salary=%s WHERE id=%s", (salary, user_id))
        mydb.commit()
        flash("Salary updated successfully!", "success")
        return redirect(url_for('monthly_salary'))

    cursor.close()
    return render_template('monthly_salary.html', theme=theme)

# ---------- ADD EXPENSE ----------
@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if 'username' not in session:
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')
    username = session['username']

    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()[0]

    if request.method == 'POST':
        title = request.form['title']
        amount = request.form['amount']
        category = request.form['category']
        date = request.form['date']
        description = request.form['description']

        cursor.execute("""
            INSERT INTO expenses (user_id, title, amount, category, date, description)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, title, amount, category, date, description))
        mydb_conn.commit()
        flash("Expense added successfully!", "success")
        return redirect(url_for('view_expenses'))

    cursor.close()
    mydb_conn.close()
    return render_template('add_expense.html', theme=theme)

# ---------- VIEW EXPENSES ----------
@app.route('/view_expenses', methods=['GET'])
def view_expenses():
    if 'username' not in session:
        flash("Please login first.", "warning")
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')
    username = session['username']
    cursor = mydb.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()['id']

    categories = [
        ("Food", "🍔 Food"),
        ("Entertainment", "🎬 Entertainment"),
        ("Health", "💊 Health"),
        ("Bills", "💡 Bills"),
        ("Travel", "🚗 Travel"),
        ("Shopping", "🛍️ Shopping"),
        ("Other", "📦 Other")
    ]

    selected_category = request.args.get('category', 'All')
    total_spent = 0

    if selected_category != 'All':
        cursor.execute("SELECT * FROM expenses WHERE user_id=%s AND category=%s ORDER BY date DESC", (user_id, selected_category))
        expenses = cursor.fetchall()
        cursor.execute("SELECT COALESCE(SUM(amount),0) AS total FROM expenses WHERE user_id=%s AND category=%s", (user_id, selected_category))
        total_spent = cursor.fetchone()['total']
    else:
        cursor.execute("SELECT * FROM expenses WHERE user_id=%s ORDER BY date DESC", (user_id,))
        expenses = cursor.fetchall()

    cursor.close()
    return render_template("view_expenses.html", theme=theme, expenses=expenses, categories=categories, selected_category=selected_category, total_spent=total_spent)

# ---------- SEARCH EXPENSES ----------
@app.route('/search_expenses', methods=['GET', 'POST'])
def search_expenses():
    if 'username' not in session:
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')
    username = session['username']
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()['id']

    cursor.execute("SELECT DISTINCT category FROM expenses WHERE user_id=%s", (user_id,))
    categories = [row['category'] for row in cursor.fetchall()]

    query = "SELECT * FROM expenses WHERE user_id=%s"
    params = [user_id]

    if request.method == 'POST':
        category = request.form.get('category')
        date = request.form.get('date')
        if category:
            query += " AND category=%s"
            params.append(category)
        if date:
            query += " AND date=%s"
            params.append(date)

    cursor.execute(query, params)
    expenses = cursor.fetchall()
    cursor.close()
    mydb_conn.close()

    return render_template('search_expenses.html', theme=theme, expenses=expenses, categories=categories, category=request.form.get('category',''), date=request.form.get('date',''))

# ---------- SEND MAIL HELPER ----------
def send_mail(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    mail.send(msg)

# ---------- FORGOT PASSWORD ----------
@app.route('/fgtpwd',methods=['GET','POST'])
def fgtpwd():
    theme = session.get('theme', 'dark')
    if request.method=='POST':
        user_email=request.form['email']
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select count(*) from users where usermail=%s',[user_email])
        count_usermail=cursor.fetchone()
        if count_usermail[0]==1:
            subject='Reset link for password update'
            body=f"Use the given reset link for password update {url_for('confirmpwd',udata=endata(data=user_email),_external=True)}"
            send_mail(to=user_email,subject=subject,body=body)
            flash(f'Reset link has been sent to {user_email}')
            return redirect(url_for('fgtpwd'))
        elif count_usermail[0]==0:
            flash('User email not found. Please check email')
            return redirect(url_for('register'))
    return render_template('forgot_password.html', theme=theme)

@app.route('/confirmpwd/<udata>', methods=['GET', 'PUT', 'POST'])
def confirmpwd(udata):
    theme = session.get('theme', 'dark')
    if request.method in ['PUT', 'POST']:
        npwd = request.form.get('password') or request.get_json().get('password')
        de_udata = dedata(udata)
        hashed_pw = generate_password_hash(npwd)
        cursor = mydb.cursor(buffered=True)
        cursor.execute('UPDATE users SET password=%s WHERE usermail=%s', [hashed_pw, de_udata])
        mydb.commit()
        cursor.close()
        flash('Your new password has been updated successfully. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('npassword.html', theme=theme, udata=udata)

# ---------- EXPENSE CRUD (edit/delete) ----------
@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
def edit_expense(expense_id):
    if 'username' not in session:
        flash("Please login first.", "warning")
        return redirect(url_for('login'))

    theme = session.get('theme', 'dark')
    cursor = mydb.cursor(dictionary=True)
    if request.method == 'POST':
        title = request.form['title']
        amount = request.form['amount']
        category = request.form['category']
        date = request.form['date']
        description = request.form['description']
        cursor.execute("""
            UPDATE expenses SET title=%s, amount=%s, category=%s, date=%s, description=%s WHERE id=%s
        """, (title, amount, category, date, description, expense_id))
        mydb.commit()
        cursor.close()
        flash("Expense updated successfully!", "success")
        return redirect(url_for('view_expenses'))

    cursor.execute("SELECT * FROM expenses WHERE id=%s", (expense_id,))
    expense = cursor.fetchone()
    cursor.close()
    return render_template('edit_expense.html', theme=theme, expense=expense)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
def delete_expense(expense_id):
    if 'username' not in session:
        flash("Please login first.", "warning")
        return redirect(url_for('login'))

    cursor = mydb.cursor()
    cursor.execute("DELETE FROM expenses WHERE id=%s", (expense_id,))
    mydb.commit()
    cursor.close()
    flash("Expense deleted successfully!", "success")
    return redirect(url_for('view_expenses'))

# ---------- SAVINGS MODULE ----------
@app.route('/add_saving', methods=['GET', 'POST'])
def add_saving():
    if 'username' not in session:
        return redirect(url_for('login'))
    theme = session.get('theme', 'dark')
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor()
    username = session['username']
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()[0]

    if request.method == 'POST':
        goal_name = request.form['goal_name']
        target_amount = request.form['target_amount']
        saved_amount = request.form.get('saved_amount', 0)
        deadline = request.form['deadline']
        saving_type = request.form['type']

        if not goal_name or not target_amount:
            flash("Goal name and target amount are required.", "danger")
            return redirect(url_for('add_saving'))

        cursor.execute("""
            INSERT INTO savings_goals (user_id, goal_name, target_amount, saved_amount, deadline, type)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, goal_name, target_amount, saved_amount, deadline, saving_type))
        mydb_conn.commit()
        flash("Saving goal added successfully.", "success")
        return redirect(url_for('view_savings'))

    return render_template('add_saving.html', theme=theme)

@app.route('/view_savings')
def view_savings():
    if 'username' not in session:
        return redirect(url_for('login'))
    theme = session.get('theme', 'dark')
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor(dictionary=True)
    username = session['username']
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()['id']

    cursor.execute("SELECT * FROM savings_goals WHERE user_id=%s ORDER BY deadline ASC", (user_id,))
    savings = cursor.fetchall()
    return render_template('view_savings.html', theme=theme, savings=savings)

# ---------- UPDATE & DELETE SAVINGS ----------
@app.route('/update_saving/<int:id>', methods=['GET', 'POST'])
def update_saving(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    theme = session.get('theme', 'dark')
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor(dictionary=True)
    username = session['username']
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()['id']

    cursor.execute("SELECT * FROM savings_goals WHERE id=%s AND user_id=%s", (id, user_id))
    saving = cursor.fetchone()
    if not saving:
        flash("Saving goal not found.", "danger")
        return redirect(url_for('view_savings'))

    if request.method == 'POST':
        goal_name = request.form['goal_name']
        target_amount = request.form['target_amount']
        saved_amount = request.form['saved_amount']
        deadline = request.form['deadline']
        saving_type = request.form['type']

        if not goal_name or not target_amount:
            flash("Goal name and target amount are required.", "danger")
            return redirect(url_for('update_saving', id=id))

        cursor.execute("""
            UPDATE savings_goals
            SET goal_name=%s, target_amount=%s, saved_amount=%s, deadline=%s, type=%s
            WHERE id=%s AND user_id=%s
        """, (goal_name, target_amount, saved_amount, deadline, saving_type, id, user_id))
        mydb_conn.commit()
        flash("Saving goal updated successfully.", "success")
        return redirect(url_for('view_savings'))

    return render_template('update_saving.html', theme=theme, saving=saving)

@app.route('/delete_saving/<int:id>')
def delete_saving(id):
    if 'username' not in session:
        return redirect(url_for('login'))
    theme = session.get('theme', 'dark')
    mydb_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin",
        database="expense_manager"
    )
    cursor = mydb_conn.cursor()
    username = session['username']
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    user_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM savings_goals WHERE id=%s AND user_id=%s", (id, user_id))
    record = cursor.fetchone()
    if not record:
        flash("Saving goal not found or unauthorized access.", "danger")
        return redirect(url_for('view_savings'))

    cursor.execute("DELETE FROM savings_goals WHERE id=%s AND user_id=%s", (id, user_id))
    mydb_conn.commit()
    flash("Saving goal deleted successfully.", "success")
    return redirect(url_for('view_savings'))

# ---------- RUN APP ----------
if __name__ == '__main__':
    app.run(debug=True)
