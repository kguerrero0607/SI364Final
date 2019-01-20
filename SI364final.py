#######################
######## SETUP ########
#######################

import os
import requests
import json
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectMultipleField, PasswordField, BooleanField, ValidationError
from wtforms.validators import Required, Length, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.debug = True

app.config['SECRET_KEY'] = 'supersecretstring'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/364Final"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

manager = Manager(app)
db = SQLAlchemy(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)


######################################
########## HELPER FUNCTIONS ##########
######################################

def get_all_queens():
    baseurl = 'http://www.nokeynoshade.party/api/queens/all'
    response = requests.get(baseurl)
    json_obj = json.loads(response.text)

    return json_obj

def get_queenid_from_api(name):
    response = requests.get('http://www.nokeynoshade.party/api/queens', params={
               'name': name
               })
    json_obj = json.loads(response.text)

    return json_obj

def get_queen_api_info(queen_id):
    url = 'http://www.nokeynoshade.party/api/queens/{}'.format(queen_id)
    response = requests.get(url)
    json_obj = json.loads(response.text)

    return json_obj

def get_challenge_api_info(challenge_id):
    challenge_url = 'http://www.nokeynoshade.party/api/challenges/{}'.format(challenge_id)
    challenge_response = requests.get(challenge_url)
    challenge_json_obj = json.loads(challenge_response.text)

    return challenge_json_obj

def get_episode_api_info(episode_id):
    episode_url = 'http://www.nokeynoshade.party/api/episodes/{}'.format(episode_id)
    episode_response = requests.get(episode_url)
    episode_json_obj = json.loads(episode_response.text)

    return episode_json_obj

def get_or_create_queen(name):
    queen = Queen.query.filter_by(name=name).first()

    if not queen:
        queen_id = get_queenid_from_api(name)[0]['id']
        queen = Queen(id=queen_id, name=name)

        queen_json_obj = get_queen_api_info(queen_id)

        # get list of ids of all maxi challenges given queen won
        maxi_victory_id_list = []
        maxi_challenge_list = queen_json_obj['challenges']
        for x in maxi_challenge_list:
            if x['type'] == 'main':
                if x['won'] == True:
                    maxi_victory_id_list.append(x['id'])

        # get list of ids of all mini challenges given queen won
        mini_victory_id_list = []
        mini_challenge_list = queen_json_obj['challenges']
        for x in mini_challenge_list:
            if x['type'] == 'mini':
                if x['won'] == True:
                    mini_victory_id_list.append(x['id'])

        # search API for challenge ID to get description, prize, and episode ID
        for x in maxi_victory_id_list:
            maxi_challenge_json_obj = get_challenge_api_info(x)

            maxi_description = maxi_challenge_json_obj['description']
            maxi_prize = maxi_challenge_json_obj['prize']
            maxi_episode_id = maxi_challenge_json_obj['episodeId']

            # search API using ep ID to get episode ep title
            maxi_episode_json_obj = get_episode_api_info(maxi_episode_id)
            maxi_ep_title = maxi_episode_json_obj['title']

            maxi_challenge = get_or_create_maxi_challenge(x,maxi_ep_title,maxi_description,maxi_prize)
            queen.maxis.append(maxi_challenge)

        # search API for challenge ID to get description, prize, and episode ID
        for x in mini_victory_id_list:
            mini_challenge_json_obj = get_challenge_api_info(x)

            mini_description = mini_challenge_json_obj['description']
            mini_prize = mini_challenge_json_obj['prize']
            mini_episode_id = mini_challenge_json_obj['episodeId']

            # search API using ep ID to get episode ep title
            mini_episode_json_obj = get_episode_api_info(mini_episode_id)
            mini_ep_title = mini_episode_json_obj['title']

            mini_challenge = get_or_create_mini_challenge(x,mini_ep_title,mini_description,mini_prize)

            queen.minis.append(mini_challenge)

        db.session.add(queen)
        db.session.commit()
    return queen

def get_or_create_quote(queen_id):
    quote = Quote.query.filter_by(queen_id=queen_id).first()

    if not quote:
        queen_json_obj = get_queen_api_info(queen_id)
        text = queen_json_obj['quote']
        quote = Quote(text=text,queen_id=queen_id)
        db.session.add(quote)
        db.session.commit()

    return quote

def get_or_create_maxi_challenge(id,ep_title,desc,prize):
    challenge = MaxiChallenge.query.filter_by(id=id).first()

    if not challenge:
        challenge = MaxiChallenge(id=id,ep_title=ep_title,description=desc,prize=prize)
        db.session.add(challenge)
        db.session.commit()

    return challenge

def get_or_create_mini_challenge(id,ep_title,desc,prize):
    challenge = MiniChallenge.query.filter_by(id=id).first()

    if not challenge:
        challenge = MiniChallenge(id=id,ep_title=ep_title,description=desc,prize=prize)
        db.session.add(challenge)
        db.session.commit()

    return challenge

def get_or_create_saved_queen_collection(name,current_user,queen_list=[]):
    collection = PersonalQueenCollection.query.filter_by(name=name,user_id=current_user.id).first()
    if not collection:
        collection = PersonalQueenCollection(name=name, user_id=current_user.id)
        for x in queen_list:
            queen = get_or_create_queen(get_queen_api_info(x)['name'])
            collection.queens.append(queen)
        db.session.add(collection)
        db.session.commit()

    return collection



##################
##### MODELS #####
##################

# association tables
queen_minis = db.Table('queen_minis', db.Column('mini_id', db.Integer, db.ForeignKey('mini_challenges.id')), db.Column('queen_id', db.Integer, db.ForeignKey('queens.id')))

queen_maxis = db.Table('queen_maxis', db.Column('maxi_id', db.Integer, db.ForeignKey('maxi_challenges.id')), db.Column('queen_id', db.Integer, db.ForeignKey('queens.id')))

users_queens = db.Table('user_collection', db.Column('queen_collection_id', db.Integer, db.ForeignKey('queen_collections.id')), db.Column('queen_id', db.Integer, db.ForeignKey('queens.id')))

# user model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, index=True)
    password_hash = db.Column(db.String(128))
    queen_collections = db.relationship('PersonalQueenCollection',backref='user')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# other models
class Queen(db.Model):
    __tablename__ = 'queens'
    id = db.Column(db.Integer, primary_key=True, autoincrement=False) # autoincrement not needed - API provides unique ID for each queen
    name = db.Column(db.String)

    # one to many relationship w quotes
    quotes = db.relationship('Quote', backref='queen')
    # many to many relationship w mini challenges
    minis = db.relationship('MiniChallenge', secondary=queen_minis, backref=db.backref('queens', lazy='dynamic'), lazy='dynamic')
    # many to many relationship w maxi challenges
    maxis = db.relationship('MaxiChallenge', secondary=queen_maxis, backref=db.backref('queens', lazy='dynamic'), lazy='dynamic')

class Quote(db.Model):
    __tablename__ = 'quotes'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String, default = 'None')
    queen_id = db.Column(db.Integer, db.ForeignKey('queens.id'))

    def __repr__(self):
        return 'QueenID: {}, Quote: {}'.format(queen_id, text)


class MiniChallenge(db.Model):
    __tablename__ = 'mini_challenges'
    id = db.Column(db.Integer, primary_key=True, autoincrement=False) # autoincrement not needed - API provides unique ID for each challenge
    ep_title = db.Column(db.String, default = 'None')
    description = db.Column(db.String, default = 'None')
    prize = db.Column(db.String, default = 'None')


class MaxiChallenge(db.Model):
    __tablename__ = 'maxi_challenges'
    id = db.Column(db.Integer, primary_key=True, autoincrement=False) # autoincrement not needed - API provides unique ID for each challenge
    ep_title = db.Column(db.String, default = 'None')
    description = db.Column(db.String, default = 'None')
    prize = db.Column(db.String, default = 'None')

    def __repr__(self):
        return 'ID: {}, Episode: {}, Desc: {}, Prize: {}'.format(id,ep_title,description,prize)

class PersonalQueenCollection(db.Model):
    __tablename__ = 'queen_collections'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))

    # one to many relationship with user
    user_id = db.Column(db.Integer,db.ForeignKey('users.id'))

    # many to many relationship w queens
    queens = db.relationship('Queen', secondary=users_queens, backref=db.backref('queens', lazy='dynamic'), lazy='dynamic')


###################
###### FORMS ######
###################

class QueenSearchForm(FlaskForm):
    name = StringField("Search for a RuPaul's Drag Race queen (please use proper capitalization): ", validators=[Required()])
    submit = SubmitField()

    # custom validator to ensure queen entered was actually a RPDR queen
    def validate_name(self, field):
        full_queen_list = []
        for x in get_all_queens():
            full_queen_list.append(x['name'])

        if field.data not in full_queen_list:
            raise ValidationError('ERROR: Name entered is not a valid RPDR queen!')

class ListCreateForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    queen_picks = SelectMultipleField('Queens to save to your list', coerce=int)
    submit = SubmitField("Save queens")

    # custom validator to prevent user from picking the worst queen in history of RPDR
    def validate_queen_picks(self, field):
        if 24 in field.data:
            raise ValidationError("ERROR: You're not allowed to pick Tyra because she's mean and no one likes her.")

class RegistrationForm(FlaskForm):
    username = StringField('Username:',validators=[Required(),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class DeleteButtonForm(FlaskForm):
    submit = SubmitField('Delete')

class UpdateButtonForm(FlaskForm):
    submit = SubmitField('Update')

class UpdateInfoForm(FlaskForm):
    new_name = StringField("What is the new name of the collection?", validators=[Required()])
    submit = SubmitField('Update')


############################
###### VIEW FUNCTIONS ######
############################

# error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# login/out related
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/', methods=['GET','POST'])
def index():
    form = QueenSearchForm()
    name = ''

    if form.validate_on_submit():
        name = form.name.data

        # specific_queen = Queen.query.filter_by(name=name).first()
        queen = get_or_create_queen(name)
        quote = get_or_create_quote(queen.id)

        return redirect(url_for('queen_info',name='{}'.format(name)))

    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))

    return render_template('index.html',form=form)

@app.route('/<name>')
def queen_info(name):
    name = name.replace('%20', ' ')
    specific_queen = Queen.query.filter_by(name=name).first()

    if not specific_queen:
        flash("That queen wasn't found. Try searching her name!")
        return redirect(url_for('index'))

    maxi_challenges_won = [(x.ep_title, x.description) for x in specific_queen.maxis.all()]
    mini_challenges_won = [(x.ep_title, x.description) for x in specific_queen.minis.all()]

    quotes = Quote.query.filter_by(queen_id=specific_queen.id).all()

    return render_template('queen_info.html', queen=specific_queen, maxi_chal=maxi_challenges_won, mini_chal=mini_challenges_won, quotes=quotes)

@app.route('/all_queens')
def all_queens():
    queen_names = []
    all_queens = Queen.query.all()
    for x in all_queens:
        queen_names.append(x.name)
    queen_names = sorted(queen_names)

    return render_template('all_queens.html', queens=queen_names)

@app.route('/mini_challenges')
def mini_challenges():
    queens = Queen.query.all()
    mini_challenges = []
    for x in queens:
        for c in x.minis.all():
            mini_challenges.append((c.ep_title, c.description, c.prize, x.name))

    return render_template('mini_challenges.html', mini_challenges=mini_challenges)

@app.route('/maxi_challenges')
def maxi_challenges():
    queens = Queen.query.all()
    maxi_challenges = []
    for x in queens:
        for c in x.maxis.all():
            maxi_challenges.append((c.ep_title, c.description, c.prize, x.name))

    return render_template('maxi_challenges.html', maxi_challenges=maxi_challenges)

@app.route('/create_saved_queens',methods=["GET","POST"])
@login_required
def create_saved_queens():
    form = ListCreateForm()
    queens = Queen.query.all()
    choices = [(q.id, q.name) for q in queens]
    form.queen_picks.choices = choices

    if form.validate_on_submit():
        queen_list = [x for x in form.queen_picks.data]
        collection = get_or_create_saved_queen_collection(form.name.data,current_user,queen_list)

        return redirect(url_for('saved_collections'))

    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))

    return render_template('create_saved_queens.html', form=form)

@app.route('/saved_collections',methods=["GET","POST"])
@login_required
def saved_collections():
    formdel = DeleteButtonForm()
    formup = UpdateButtonForm()

    return render_template('saved_collections.html', collections=current_user.queen_collections,formup=formup,formdel=formdel)

@app.route('/delete/<name>', methods=["GET","POST"])
@login_required
def delete_collection(name):
    c = PersonalQueenCollection.query.filter_by(name=name).first()
    db.session.delete(c)
    db.session.commit()
    flash("Successfully deleted")
    return redirect(url_for('saved_collections'))

@app.route('/update/<name>', methods = ['GET','POST'])
def update_collection(name):
    form = UpdateInfoForm()
    if form.validate_on_submit():
        new_name = form.new_name.data
        c = PersonalQueenCollection.query.filter_by(name=name).first()
        c.name = new_name
        db.session.commit()
        flash("Updated title of " + name)
        return redirect(url_for('saved_collections'))
    return render_template('update_info.html',coll_name = name, form = form)


if __name__ == '__main__':
    db.create_all()
    app.run(use_reloader=True,debug=True)
    manager.run()
