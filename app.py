import random

from flask.ext.bcrypt import Bcrypt
from flask import Flask, redirect,render_template, request, session, url_for


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    dicerolls = db.Column(db.Integer)

    def create(self, username, password):
        pw_hash = bcrypt.generate_password_hash(password)
        new_user = User(username=username, password=pw_hash, dicerolls=0)
        db.session.add(new_user)
        db.session.commit()

        return new_user

    def login(self, username, password):
        user = User.query.filter_by(username=username).first()

        if bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return None

    def validate_info(self, username, password):
        if not username:
            return False
        if not password:
            return False

        # Create check.
        # Check if user exists in DB
        if User.query.filter_by(username=username).first() is not None:
            return False

        return True


db.create_all()

# Landing page
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Sign-in page
@app.route('/signin', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'GET':
        return render_template('signin.html')
    else:
        # Get user info from form
        username = request.form['username']
        password = request.form['password']
        
        if user_auth(username, password):
            # Create session
            session['uid'] = user.id

            return redirect('/')

# End point to sign out user
@app.route('/signout', methods=['POST'])
def sign_out():
    session.clear()


# Game logic
@app.route('/roll', methods=['POST'])
def roll():
    roll_num = random.randint(1, 6)

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)


