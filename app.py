from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from datetime import datetime
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, DateField
from wtforms.validators import DataRequired
from wtforms.validators import DataRequired, Optional

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///libraryhub.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    review = TextAreaField('Review')
    borrow_date = DateField('Borrow Date', format='%Y-%m-%d', validators=[Optional()])
    return_date = DateField('Return Date', format='%Y-%m-%d', validators=[Optional()])
    submit = SubmitField('Add Book')



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    review = db.Column(db.Text, nullable=True)  # New field for review
    borrow_date = db.Column(db.Date, nullable=True)  # New field for borrow date
    return_date = db.Column(db.Date, nullable=True)  # New field for return date
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)

        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            return render_template('error.html', message="Your username or password is not correct")
    return render_template('login.html', form=form)


@app.route('/edit-book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    if request.method == 'POST':
        book.title = request.form['title']
        book.author = request.form['author']
        book.review = request.form.get('review')
        book.borrow_date = datetime.strptime(request.form['borrow_date'], '%Y-%m-%d').date() if request.form['borrow_date'] else None
        book.return_date = datetime.strptime(request.form['return_date'], '%Y-%m-%d').date() if request.form['return_date'] else None
        db.session.commit()
        flash('Book updated successfully!')
        return redirect(url_for('dashboard'))
    return render_template('edit_book.html', book=book)

@app.template_filter('format_date')
def format_date(value, format='%Y-%m-%d'):
    """Format a date for displaying in HTML input fields."""
    if value is not None:
        return value.strftime(format)
    return ''



@app.route('/delete-book/<int:book_id>')
@login_required
def delete_book(book_id):
    book = Book.query.get(book_id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = BookForm()
    if form.validate_on_submit():
        try:
            # Check if dates are provided and convert them if necessary
            borrow_date = form.borrow_date.data
            return_date = form.return_date.data

            new_book = Book(
                title=form.title.data,
                author=form.author.data,
                review=form.review.data,
                borrow_date=borrow_date,
                return_date=return_date,
                user_id=current_user.id
            )
            db.session.add(new_book)
            db.session.commit()
            flash('Book added successfully!', 'success')
        except Exception as e:
            flash(str(e), 'danger')
            return render_template('dashboard.html', form=form)

    books = Book.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', form=form, books=books)

@app.template_filter('to_string')
def to_string(value):
    return value.strftime('%Y-%m-%d') if value else ''




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
