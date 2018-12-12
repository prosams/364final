
# Sam Lu SI 364
# I referenced code from HW 3 for this
# also code from the WTForms example with itunes
# also code from the get - or - create example
# https://www.pythonsheets.com/notes/python-sqlalchemy.html

###############################
####### SETUP (OVERALL) #######
###############################

## Import statements
import os
import requests
import json
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, RadioField, ValidationError, FileField, PasswordField, BooleanField, SelectMultipleField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from goog_api_key import api_key

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

## App setup code
app = Flask(__name__)
app.debug = True

## All app.config values
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/finaldb"
## Provided:
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

## Statements for db setup (and manager setup if using Manager)
db = SQLAlchemy(app)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

######################################
######## HELPER FXNS (If any) ########
######################################

# takes in city or state and then checks if there's something in the Locations table with those parts
def get_or_create_location(city, state):
    location = db.session.query(Locations).filter_by(city=city).first()
    if location: # if the thing already exists, does not commit
        return location
    else:
        newloc = Locations(city = city, state = state) #if the thing does not already exist, adds to database and then returns it
        db.session.add(newloc)
        db.session.commit()
        return newloc

def get_station_by_id(id):
	"""Should return station object or None"""
	g = Gassy.query.filter_by(id=id).first()
	return g

def get_or_create_collection(name, current_user, stationlist=[]):
	"""Always returns a PersonalCollection instance"""
	collec = PersonalCollection.query.filter_by(title = name, userid = current_user.id).first()

	if collec: 			# if there exists a collection with the input name, associated with the current user,
		return collec 	#then this function should return that PersonalCollection instance.

	else:
		newcollec = PersonalCollection(title = name, userid = current_user.id, stations = stationlist)
		for station in stationlist:
			newcollec.gasstations.append(station)
		db.session.add(newcollec)
		db.session.commit()
		return newcollec

##################
##### MODELS #####
##################

user_collection = db.Table('user_collection',db.Column('gas_id',db.Integer,db.ForeignKey('gasstations.gasid')),db.Column('collection_id',db.Integer,db.ForeignKey('PersonalCollection.id')))

# Special model for users to log in
class User(UserMixin, db.Model): # REMEMBER THAT YOU NEED TO CHANGE THIS DB RELATIONSHIP THING
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(255), unique=True, index=True)
	email = db.Column(db.String(64), unique=True, index=True)
	password_hash = db.Column(db.String(128))
	collection = db.relationship("PersonalCollection", backref="Users") # one user, many personal collections of stations with different names"
	# Remember, the best way to do so is to add the field, save your code, and then create and run a migration!
	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

## DB load function - Necessary for behind the scenes login manager that comes with flask_login capabilities! Won't run without this.
@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id)) # returns User object or None

class Gassy(db.Model): #each individual gas station has one location
    __tablename__ = "gasstations"
    gasid = db.Column(db.Integer, primary_key=True)
    gasname = db.Column(db.String(64)) #name of the gas station
    road = db.Column(db.String(64))
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    location_id = db.Column(db.Integer, db.ForeignKey('locations.locationid'))

    def __repr__(self):
        return "#{}. {} at {}.".format(self.gasid, self.gasname, self.road)

class Locations(db.Model): # one location can have many gas stations
    __tablename__ = "locations"
    locationid = db.Column(db.Integer, primary_key=True) #
    city = db.Column(db.String(64))
    state = db.Column(db.String(64))
    gasses = db.relationship("Gassy", backref='Locations')

    def __repr__(self):
        return "{}, {} (ID: {})".format(self.city, self.state, self.locationid)

# Model to store a personal collection
class PersonalCollection(db.Model):
	__tablename__ = "PersonalCollection"
	# TODO 364: Add code for the PersonalCollection model such that it has the following fields:
	id = db.Column(db.Integer, primary_key=True)        # id (Integer, primary key)
	title = db.Column(db.String(255))      # name (String, up to 255 characters)
	userid = db.Column(db.Integer, db.ForeignKey('users.id'))    # one-to-many relationship with the User model (one user, many personal collections of stations with different names)
	stations = db.relationship('Gassy',secondary=user_collection,backref=db.backref("PersonalCollection",lazy='dynamic'),lazy='dynamic')
	# many to many rselationship with the gassy model (one station in many personal collections, one personal collection has many stations in it).

class Opinion(db.Model): #a table that is filled with user opinions on gas stations etc
    __tablename__ = "opinion"
    opinionid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    rating = db.Column(db.String(64))
    comments = db.Column(db.String(64))

    def __repr__(self):
        return "#{}. [{}] has a rating of {} and your comments were: {}".format(self.opinionid, self.name, self.rating, self.comments)

###################
###### FORMS ######
###################

class RegistrationForm(FlaskForm):
	email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
	username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	submit = SubmitField('Register User')

	#Additional checking methods for the form
	def validate_email(self,field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already registered.')

	def validate_username(self,field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log In')

class CollectionCreateForm(FlaskForm):
	name = StringField('Collection Name',validators=[Required()])
	station_picks = SelectMultipleField('Stations to include')
	submit = SubmitField("Create Collection")

class PlaceForm(FlaskForm):
    location = StringField("Please enter the place you want to search for — ideally, city. ", validators=[Required(), Length(min=0,  max=64)])
    type = StringField("Please enter the brand you want to look up followed by 'gas station' (ie. Shell gas station or just 'gas station' if brand doesn't matter)", validators=[Required(), Length(min=0,  max=64)])
    submit = SubmitField("Submit")

    def validate_location(self, field): # TODO 364: Set up custom validation for this form
        displaydata = field.data
        splitcheck = displaydata.split(" ")
        if len(splitcheck) >  5: #your name of the location cannot exceed 5 words! ! !
            raise ValidationError("The name of your location cannot exceed 5 words.")

    def validate_type(self, field): # TODO 364: Set up custom validation for this form
        displaydata = field.data
        if "gas station" not in displaydata:
            raise ValidationError("You must have 'gas station' within your second input!")

class OpinionForm(FlaskForm):
    name = StringField("Please enter the name or a description of a station you want to leave an opinion about: ", validators=[Required(), Length(min=0,  max=64)])
    rating = StringField('Please enter your rating out of 10 (1 low, 10 high)', validators=[Required(),  Length(min=0,  max=2)])
    comments = StringField("Please enter any comments you have about the station", validators=[Required(), Length(min=0,  max=128)])
    submit = SubmitField("Submit")

class UpdateButtonForm(FlaskForm):
    submit = SubmitField("Update")

class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete")

class UpdateRatingForm(FlaskForm):
    newPriority = StringField("What is the new rating of the gas station?", validators=[Required()])
    submit = SubmitField('Update')

## Error handling routes - THIS IS COPIED FROM HOMEWORK 3
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

#######################
###### VIEW FXNS ######
#######################

@app.route('/login',methods=["GET","POST"])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.args.get('next') or url_for('index'))
		flash('Invalid username or password.')
	return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out')
	return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email=form.email.data,username=form.username.data,password=form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('You can now log in!')
		return redirect(url_for('login'))
	return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
	return "Only authenticated users can do this! Try to log in or contact the site admin."

@app.route('/')
def index():
    form = PlaceForm()
    return render_template('index.html',form=form)

@app.route('/results', methods=['GET', 'POST'])
def results(): # all the results (after calls made to google place api, this should be what shows up)
    form = PlaceForm(request.form)

    if request.method == 'POST' and form.validate_on_submit():
        biglist = [] # this is the final list that will be iterated through to return the results from the search
        url = "https://maps.googleapis.com/maps/api/place/textsearch/json?"
        key = api_key
        params = {}

        location = form.location.data #change this if it changes to get
        specifics = form.type.data
        searchstring = specifics + " " + location
        params["query"] = searchstring
        params["key"] = key
        response = requests.get(url, params)
        result = response.json()

        for x in result["results"]:
            locationdict = x["geometry"]["location"]
            locstring = str(locationdict["lat"]) + "," + str(locationdict["lng"])
            lat = locationdict["lat"]           #lat of gas station
            long = locationdict["lng"]          #longitude of gas station
            name = x["name"]                    # name of the gas station
            address = x["formatted_address"]
            splitad = address.split(",")        # this is just for getting individual bits
            road = splitad[0]                   # road address of gas station
            city = splitad[1]                   #city of gas station - to go into the Locations table
            state = splitad[2].split()[0]       #state of gas station - to go in locations table

            newloc = get_or_create_location(city, state) #need to check this every time because even though the original query is the same city, not all of the results will be from the same city (sometimes they just give all neighboring)
            # newgas = get_or_create_gas(gasname = name, road = road, lat = lat, long = long, location_id = newloc.locationid)
            newgas = Gassy(gasname = name, road = road, lat = lat, long = long, location_id = newloc.locationid)
            db.session.add(newgas)
            db.session.commit()

            biglist.append((name, road, city, state)) # appends a tuple with information about each of the individual gas stations to the final list of tuples
        return render_template('results.html', finaltuplist = biglist)
    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))
    return redirect(url_for('index'))

@app.route('/all_gas')
def all_gas():
    stats = Gassy.query.all()
    return render_template('stations.html', stations=stats)

@app.route('/all_loc')
def all_loc():
    locs = Locations.query.all()
    return render_template('searchedlocations.html', locations=locs)

@app.route('/opinion',  methods=['GET'])
def opinion():
    form = OpinionForm()
    return render_template('opinion.html', form=form)

@app.route('/opinionresults',  methods=['GET', 'POST'])
def opinionresults():
    form = OpinionForm(request.form)
    name = request.args.get('name')
    rating = request.args.get('rating')
    comments = request.args.get("comments")

    new = Opinion(name=name, rating=rating, comments=comments)
    db.session.add(new)
    db.session.commit()

    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))

    return render_template("opinionresults.html", name = name, rating = rating, comments = comments)

@app.route('/all_ops')
def allops():
    all = Opinion.query.all()
    return render_template('allops.html', all=all)

@app.route('/create_collection',methods=["GET","POST"])
@login_required
def create_collection():
	form = CollectionCreateForm()
	stations = Gassy.query.all()
	choices = [(g.id, g.title) for g in stations]
	form.station_picks.choices = choices

	if request.method == "POST":
		stationlist = form.station_picks.data
		name = form.name.data
		listed = [get_station_by_id(int(individual)) for individual in stationlist] # create a list of station objects
		collec = get_or_create_collection(name = name, current_user = current_user, stationlist = listed)
		return redirect(url_for('collections'))

	# TODO 364: If the form validates on submit, get the list of the gas ids that were selected from the form. Use the get_station_by_id function to .  Then, use the information available to you at this point in the function (e.g. the list of gif objects, the current_user) to invoke the get_or_create_collection function, and redirect to the page that shows a list of all your collections.
	# If the form is not validated, this view function should simply render the create_collection.html template and send the form to the template.
	return render_template('create_collection.html', form = form)

@app.route('/collections',methods=["GET","POST"])
@login_required
def collections():
	currentcollection = PersonalCollection.query.filter_by(userid = current_user.id).all()
	return render_template('collections.html', collections = currentcollection)
	# TODO 364: This view function should render the collections.html template so that only the current user's personal collection links will render in that template. Make sure to examine the template so that you send it the correct data!


if __name__ == '__main__':
    db.create_all() # Will create any defined models when you run the application
    app.run(use_reloader=True,debug=True) # The usual
