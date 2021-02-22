from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from data import db_session
from data import users
from data.users import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'project'

login_manager = LoginManager()
login_manager.init_app(app)


@app.route('/')
@app.route('/index')
def index():
    if current_user.is_authenticated:
        return redirect('/message')
    return render_template('index.html')


class RegisterForm(FlaskForm):
    name = StringField('', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField('', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    password_again = PasswordField('', validators=[DataRequired()], render_kw={"placeholder": "Confirm password"})
    submit = SubmitField('Submit')

    def validate_username(self, username):
        excluded_chars = " *?!'^+%&;/()=}][{$#"
        for char in username:
            if char in excluded_chars:
                return f"Character {char} is not allowed in username."


@app.route('/registration', methods=["GET", "POST"])
def reg():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect('/message')
    if form.validate_on_submit():
        if len(form.name.data) < 5 or len(form.name.data) > 20:  # проверка на длину имени
            return render_template('reg.html', form=form, message='Длина имени может быть от 5 до 20 символов')
        check = form.validate_username(form.name.data)  # проверка на запрещенные символы
        if check is not None:
            return render_template('reg.html', form=form, message=check)
        if form.password.data != form.password_again.data:  # проверка на совпадение паролей
            return render_template('reg.html', form=form, message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(users.User). \
                filter(users.User.name == form.name.data).first():  # проверка на то, есть ли user в базе данных
            return render_template('reg.html', form=form, message="Такой пользователь уже есть")
        user = users.User(name=form.name.data,)
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('reg.html', form=form)


class LoginForm(FlaskForm):
    name = StringField('', validators=[DataRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField('', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField('Submit')


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect('/message')
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.name == form.name.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect('/message')
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/message', methods=["GET", "POST"])
def message():
    return render_template('message.html')


@app.route('/friends')
def friends():
    return render_template('friends.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/index')


db_session.global_init("db/messengers.sqlite")
if __name__ == "__main__":
    app.run(debug=True)
