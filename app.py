from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///queue_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Initialize SQLAlchemy
db = SQLAlchemy(app)


# Database Models
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(100), nullable=True)  # Allow NULL (None)
    status = db.Column(db.String(50), default="waiting")
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cashier = db.Column(db.String(100), nullable=False)
    customer_name = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Route to display the form for creating a new user (admin or cashier)
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('create_user'))

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Create a new user
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash(f'New {role} user created successfully!', 'success')
        return redirect(url_for('admin_profile'))

    return render_template('create_user.html')
# Function to create the admin user (run this conditionally)
def create_admin_user(username, password):
    admin = Admin.query.filter_by(username=username).first()
    if admin:
        return
    hashed_password = generate_password_hash(password)
    new_admin = Admin(username=username, password=hashed_password)
    db.session.add(new_admin)
    db.session.commit()


# Initialize the database (ensure tables are created)
def init_db():
    with app.app_context():
        db.create_all()  # Creates all the tables based on the models
        create_admin_user("admin", "adminpassword")

#ROUTE FOR SEARCHING
@app.route('/search_tickets', methods=['GET'])
def search_tickets():
    search_term = request.args.get('search')
    tickets = Ticket.query.filter(
        (Ticket.id.like(f"%{search_term}%")) |
        (Ticket.customer_name.like(f"%{search_term}%"))
    ).all()
    return render_template('cashier_dashboard.html', tickets=tickets)

# Route to generate a random ticket number (without customer name)
@app.route('/generate_ticket', methods=['POST'])
def generate_ticket():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    # Create a new ticket with no customer name and status 'waiting'
    new_ticket = Ticket(customer_name=None, status='waiting')
    db.session.add(new_ticket)
    db.session.commit()

    # Using the automatically assigned ID as the ticket number
    flash(f'Random ticket #{new_ticket.id} has been created and added to the queue.', 'success')
    return redirect(url_for('admin_profile'))

@app.route('/transactions')
def transactions():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    # Fetch all transactions from the database
    transactions = Transaction.query.all()
    return render_template('transactions.html', transactions=transactions)


# Route for the home page
@app.route('/')
@app.route('/')
def home():
    # Get all tickets that are 'waiting' or 'serving' (excluding 'done')
    ticket_queue = Ticket.query.filter(Ticket.status != 'done').all()

    # Automatically mark the first "waiting" ticket as 'serving' if no ticket is being served
    current_ticket = Ticket.query.filter_by(status="serving").first()
    if not current_ticket:
        # Find the first "waiting" ticket
        first_waiting_ticket = Ticket.query.filter_by(status="waiting").first()
        if first_waiting_ticket:
            first_waiting_ticket.status = "serving"
            db.session.commit()
            current_ticket = first_waiting_ticket

    return render_template('home.html', current_ticket=current_ticket, queue=ticket_queue)





# Admin login route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            resp = make_response(redirect(url_for('admin_profile')))
            resp.set_cookie('admin', username)
            return resp
        else:
            flash('Invalid credentials, please try again!', 'danger')
    return render_template('login.html')


# Admin profile route
# Admin profile route
@app.route('/admin_profile')
def admin_profile():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    tickets = Ticket.query.all()  # Get all tickets from the database
    transactions = Transaction.query.all()  # Get all transactions
    return render_template('admin_profile.html', tickets=tickets, transactions=transactions)



# Dashboard for cashiers
# Dashboard for cashiers
@app.route('/dashboard')
def dashboard():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    # Show only tickets with "waiting" status
    tickets = Ticket.query.filter_by(status="waiting").all()
    return render_template('dashboard.html', tickets=tickets)



# Log out route
@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(redirect(url_for('admin_login')))
    resp.delete_cookie('admin')  # Delete the admin cookie
    flash('You have been logged out successfully!', 'success')
    return resp


# Serve the ticket (cashier mark ticket as done)
# Serve the ticket (cashier mark ticket as done)
# Serve the ticket (cashier mark ticket as done)
@app.route('/serve_ticket/<int:ticket_id>', methods=['POST'])
def serve_ticket(ticket_id):
    ticket = Ticket.query.get(ticket_id)

    if ticket:
        # Mark the ticket as 'done'
        ticket.status = 'done'

        # Get the cashier's name from the cookies (or you can use a session variable)
        cashier_name = request.cookies.get('admin', 'Cashier 1')  # Default to 'Cashier 1' if not set

        # Store cashier's name in the ticket
        ticket.cashier_name = cashier_name

        # Create a transaction entry for the served ticket
        if ticket.customer_name:
            transaction = Transaction(cashier=cashier_name, customer_name=ticket.customer_name)
        else:
            transaction = Transaction(cashier=cashier_name, customer_name="Unknown Customer")

        db.session.add(transaction)
        db.session.commit()

        flash(f"Ticket #{ticket.id} marked as done by {cashier_name}.", "success")
    else:
        flash(f"Ticket {ticket_id} not found.", "danger")

    return redirect(url_for('home'))  # Redirect to home to refresh the page


# Route to create a new ticket (only accessible to admin)
@app.route('/create_ticket', methods=['POST'])
def create_ticket():
    if 'admin' not in request.cookies:
        return redirect(url_for('admin_login'))

    customer_name = request.form['customer_name']
    if not customer_name:
        flash('Customer name is required for a new ticket.', 'danger')
        return redirect(url_for('admin_profile'))

    new_ticket = Ticket(customer_name=customer_name)
    db.session.add(new_ticket)
    db.session.commit()

    flash(f'Ticket for {customer_name} has been created.', 'success')
    return redirect(url_for('admin_profile'))


if __name__ == '__main__':
    init_db()  # Ensure the database is initialized and create the admin user
    app.run(debug=True)
