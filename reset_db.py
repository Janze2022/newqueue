# Import necessary modules
from app import app, db, Ticket, Transaction

def reset_system():
    # Run within the application context to have access to db
    with app.app_context():
        # Deleting all entries from the Ticket and Transaction tables
        Ticket.query.delete()
        Transaction.query.delete()

        # Commit the changes to the database
        db.session.commit()

        print("System has been reset: All tickets and transactions have been cleared.")

# Call the reset function
if __name__ == "__main__":
    reset_system()
