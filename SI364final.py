
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
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, RadioField, ValidationError# Note that you may need to import more here! Check out examples that do what you want to figure out what.
from wtforms.validators import Required, Length# Here, too
from flask_sqlalchemy import SQLAlchemy
import requests
import json

## App setup code
app = Flask(__name__)
app.debug = True

## All app.config values
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://localhost/364midterm"
## Provided:
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

## Statements for db setup (and manager setup if using Manager)
db = SQLAlchemy(app)

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

##################
##### MODELS #####
##################

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

class UserOpinion(db.Model): #a table that is filled with user opinions on gas stations etc
    __tablename__ = "useropinion"
    opinionid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    rating = db.Column(db.String(64))
    comments = db.Column(db.String(64))

    def __repr__(self):
        return "#{}. [{}] has a rating of {} and your comments were: {}".format(self.opinionid, self.name, self.rating, self.comments)

###################
###### FORMS ######
###################

class PlaceForm(FlaskForm):
    location = StringField("Please enter the place you want to search for — ideally, city. ", validators=[Required(), Length(min=0,  max=64)])
    type = StringField("Please enter the brand you want to look up followed by 'gas station' (ie. Shell gas station or just 'gas station' if brand doesn't matter)", validators=[Required(), Length(min=0,  max=64)])
    submit = SubmitField("Submit")

    def validate_name(form, field): # TODO 364: Set up custom validation for this form
        displaydata = field.data
        splitcheck = displaydata.split(" ")
        if len(splitcheck) >  5: #your name of the location cannot exceed 5 words! ! !
            raise ValidationError("The name of your location cannot exceed 5 words.")

    def validate_type(form, field): # TODO 364: Set up custom validation for this form
        displaydata = field.data
        if "gas station" not in displaydata:
            raise ValidationError("You must have 'gas station' within your second input!")

class OpinionForm(FlaskForm):
    name = StringField("Please enter the name of the station you want to leave an opinion about: ", validators=[Required(), Length(min=0,  max=64)])
    rating = StringField('Please enter your rating out of 5 (1 low, 5 high)', validators=[Required(),  Length(min=0,  max=2)])
    comments = StringField("Please enter any comments you have about the station", validators=[Required(), Length(min=0,  max=128)])
    submit = SubmitField("Submit")

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
        key = ""
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

    new = UserOpinion(name=name, rating=rating, comments=comments)
    db.session.add(new)
    db.session.commit()

    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("!!!! ERRORS IN FORM SUBMISSION - " + str(errors))

    return render_template("opinionresults.html", name = name, rating = rating, comments = comments)

@app.route('/all_ops')
def allops():
    all = UserOpinion.query.all()
    return render_template('allops.html', all=all)

if __name__ == '__main__':
    db.create_all() # Will create any defined models when you run the application
    app.run(use_reloader=True,debug=True) # The usual
