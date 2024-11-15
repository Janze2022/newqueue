class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='cashier')  # 'admin' or 'cashier'

    def __repr__(self):
        return f'<User {self.username}>'
