from flask import Flask, render_template, redirect, url_for, request, abort, send_file, flash, session, make_response
from Forms import *
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, login_required, logout_user, current_user, UserMixin
from flask_principal import Permission, Principal, Identity, AnonymousIdentity, identity_loaded, identity_changed, RoleNeed, UserNeed
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach, re

from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from markupsafe import escape
from flask_migrate import Migrate
from datetime import datetime
import stripe, imghdr, os

import pyotp, qrcode



app = Flask(__name__, static_url_path='/static')
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@localhost/flask"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1920 * 1080
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif']
app.config['UPLOAD_PATH'] = 'uploads'

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

stripe.api_key = 'sk_test_51NCNheBHsDcbGIEu417E9pEVVBgRLIE1MkxCYClUrUwJjOwodY15jeJu9UBJjMWu3ScMPLob6xQqUNrEe7gH7Qng005owAoDdZ'

db = SQLAlchemy(app)
Migrate(app,db)

app.secret_key = 'nocigarette'
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

principals = Principal(app)


@app.route('/')
def home():
    return render_template("home.html")

#Permissions
#========================================================================================
superadmin_permission = Permission(RoleNeed('superadmin'))
admin_permission = Permission(RoleNeed('admin'))
user_permission = Permission(RoleNeed('user'))


#Roles
#========================================================================================
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the User model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role))

#Joshua (Database)
#========================================================================================

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(100),nullable=False)
    username = db.Column(db.String(20), nullable=False)
    password= db.Column(db.String(200),nullable=False)
    roles = db.Column(db.JSON, nullable=False)
    otp_secret = db.Column(db.String(16), nullable=True, default='')
    otp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    user_data = db.relationship("UserData", back_populates="user", uselist=False, cascade='all, delete-orphan')

    def get_totp_uri(self):
        return 'otpauth://totp/Greengo%20Token:{0}?secret={1}&issuer=Greengo'.format(self.username, self.otp_secret)
    
    def verify_totp(self, token):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)   

class UserData(db.Model):
    __tablename__ = 'user_data'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    user = db.relationship("User", back_populates="user_data")
    name = address = db.Column(db.String(30), nullable=True)
    phone_no = db.Column(db.String(15), nullable=True)
    address = db.Column(db.String(95), nullable=True)
    profile_picture = db.Column(db.String(95), nullable=True)
    

class Location(db.Model):
    __tablename__ = 'locations'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)


class Booking(db.Model):
    __tablename__ = 'booking'
    id = db.Column(db.Integer, primary_key=True)
    location_name = db.Column(db.String(100), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

class Eco_Information(db.Model):
    __tablename__ = 'eco_information'
    id = db.Column(db.Integer, primary_key=True)
    activity = db.Column(db.String(100), nullable=True)
    description = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    image_url = db.Column(db.String(100), nullable=True)


def create_default_admin():
    superadmin = User.query.filter_by(roles=['user','admin','superadmin']).first()
    if not superadmin:
        key = pyotp.random_base32()
        password = bcrypt.generate_password_hash('password')
        new_admin = User(id=0,email='superadmin@gmail.com',username='superadmin',password=password,roles=['user','admin','superadmin'],otp_secret=key,otp_enabled=False)
        db.session.add(new_admin)
        db.session.commit()
        db.session.close()

def create_default_eco_information():
    if db.session.query(Eco_Information).count() == 0:
        data = [
        {'id': 7, 'country': 'Japan', 'city': 'Tokyo', 'activity': 'River Rafting in Gunma', 'description': 'Experience the thrill of river rafting in the beautiful Gunma prefecture. Navigate through the rapids and enjoy the stunning scenery along the river.', 'image_url': 'https://a1.cdn.japantravel.com/photo/1734-10011/800x400!/gunma-minakami-river-rafting-10011.jpg'},
        {'id': 8, 'country': 'Japan', 'city': 'Tokyo', 'activity': 'Hiking in Kansai', 'description': 'Embark on an eco-friendly hiking adventure in the picturesque Kansai region. Explore lush forests, scenic trails, and breathtaking vistas.', 'image_url': 'https://imgcp.aacdn.jp/img-a/1200/900/global-aaj-front/article/2017/03/58c27d96eaf42_58c27d6a5a8cf_1398127580.jpg'},
        {'id': 9, 'country': 'Japan', 'city': 'Tokyo', 'activity': 'Hotsprings in Hakone', 'description': 'Relax and rejuvenate in the natural hotsprings of Hakone. Enjoy the soothing waters and the tranquil ambiance of this popular spa destination.', 'image_url': 'https://www.hakonenavi.jp/international/en/wp-content/uploads/sites/2/2019/01/feature_1488_main.jpg'},
        {'id': 10, 'country': 'Vietnam', 'city': 'Hanoi', 'activity': 'Cu Lao Cham Marine Park', 'description': 'Discover the rich marine biodiversity of Cu Lao Cham Marine Park. Snorkel, dive, and witness vibrant coral reefs and colorful marine life.', 'image_url': 'https://www.vietnamonline.com/media/uploads/froala_editor/images/VNO%20cham%20island5_4MFZ8VI.jpg'},
        {'id': 11, 'country': 'Vietnam', 'city': 'Hanoi', 'activity': 'Tra Que Vegetable Village', 'description': 'Immerse yourself in the traditional farming practices of Tra Que Vegetable Village. Learn about organic cultivation and taste fresh, locally-grown produce.', 'image_url': 'https://statics.vinpearl.com/tra-que-vegetable-village-1_1648199046.jpg'},
        {'id': 12, 'country': 'Vietnam', 'city': 'Hanoi', 'activity': 'My Son Sanctuary', 'description': 'Explore the ancient ruins of My Son Sanctuary, a UNESCO World Heritage site. Experience the historical and cultural significance of this sacred place.', 'image_url': 'https://centralvietnamguide.com/wp-content/uploads/2022/02/my-son-sanctuary-2-1024x683.jpg'},
        {'id': 13, 'country': 'Thailand', 'city': 'Bangkok', 'activity': 'Bamboo Bicycle Tours', 'description': 'Go green with a bamboo bicycle tour. Enjoy a sustainable and eco-friendly ride through the city, taking in the sights and sounds along the way.', 'image_url': 'https://media-cdn.tripadvisor.com/media/photo-m/1280/1a/8b/e6/23/thailand-zoals-het-echt.jpg'},
        {'id': 14, 'country': 'Thailand', 'city': 'Bangkok', 'activity': 'Dine at zero waste restaurant Haoma', 'description': 'Indulge in a unique dining experience at the zero waste restaurant Haoma. Savor delicious dishes made from locally sourced and sustainable ingredients.', 'image_url': 'https://www.gourmetbangkok.com/wp-content/uploads/2018/08/HAOMA-15R.jpg'},
        {'id': 15, 'country': 'Thailand', 'city': 'Bangkok', 'activity': 'Bangkok Tree House', 'description': 'Escape to the Bangkok Tree House, an eco-friendly oasis in the bustling city. Stay in a treehouse and enjoy a tranquil retreat amidst nature.', 'image_url': 'https://www.uniqhotels.com/media/hotels/c5-hotel-orig/bangkok%20tree%20house.jpg.700x345_q85_box-0%2C118%2C1600%2C908_crop_detail.jpg'},
        {'id': 16, 'country': 'South Korea', 'city': 'Seoul', 'activity': 'Seoul Forest', 'description': 'Visit Seoul Forest, a green sanctuary in the heart of the city. Enjoy walking trails, beautiful landscapes, and various eco-friendly activities.', 'image_url': 'https://static.wixstatic.com/media/0505b9_6734e021c23f4699b857a2a623010ad2~mv2.jpg/v1/fill/w_640,h_500,al_c,q_80,usm_0.66_1.00_0.01,enc_auto/Seoul%20Forest%20-%20Cherry%20Blossoms%205.jpg'},
        {'id': 17, 'country': 'South Korea', 'city': 'Seoul', 'activity': 'Cheonggyecheon Stream', 'description': 'Stroll along Cheonggyecheon Stream, an urban renewal project that transformed a neglected waterway into a picturesque green space in Seoul.', 'image_url': 'https://greatruns.com/wp-content/uploads/2017/04/Cheonggyecheon-Stream.jpeg'},
        {'id': 18, 'country': 'South Korea', 'city': 'Seoul', 'activity': 'City Hall Green Wall', 'description': "Marvel at the City Hall Green Wall, a living vertical garden that showcases Seoul's commitment to sustainability and urban greening.", 'image_url': 'https://news.samsungcnt.com/wp-content/uploads/2017/10/Seoul-City-Hall-%E2%80%98Green-Wall-measuring-a-total-of-1512m2-has-the-Guinness-World-Record-for-the-largest-vertical-garden.jpg'}
        ]

        for entry in data:
            eco_info = Eco_Information(**entry)
            db.session.add(eco_info)

        db.session.commit()
        


with app.app_context():
    db.create_all()
    create_default_admin()
    create_default_eco_information()



#Joshua
#========================================================================================  
@app.before_request
def pop_flash():
    session.pop('_flashes', None)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self' *.jsdelivr.net *.stripe.com sustainabletravel.org *.cloudflare.com www.w3.org" 
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    if current_user.is_authenticated:
        response.set_cookie(current_user.username, 'flask', secure=True, httponly=True, samesite='Lax')
    return response

@login_required
@superadmin_permission.require(http_exception=403)
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def dashboard():
    users_list = User.query.all()
    return render_template('admin_dashboard.html', users_list = users_list)

@login_required
@superadmin_permission.require(http_exception=403)
@app.route('/delete_user/<userid>', methods=['GET', 'POST'])
def delete_user(userid):
    user = User.query.filter_by(id=userid).first()
    if user:
        if 'superadmin' in user.roles:
            abort(403)
        else:
            db.session.delete(user)
            db.session.commit()
    else:
        abort(403)
    return redirect(url_for('dashboard'))

@login_required
@superadmin_permission.require(http_exception=403)
@app.route('/update_user/<userid>', methods=['GET', 'POST'])
def update_user(userid):
    user = User.query.filter_by(id=userid).first()
    update_form = RegistrationForm(request.form)

    email = update_form.email.data
    username = update_form.username.data
    if request.method == 'POST' and update_form.validate() and UsernameEmailInUse(email,username) == False:
        
        password = bcrypt.generate_password_hash(update_form.password.data)

        user.email = update_form.email.data
        user.username = update_form.username.data
        user.password = password

        db.session.commit()
        
        return redirect(url_for('dashboard'))

    return render_template('update_user.html',form = update_form)

#Jonathan
#========================================================================================
#Custom Validator
def UsernameEmailInUse(email, username):
    email = User.query.filter_by(email=email).first()
    username = User.query.filter_by(username=username).first()
    if email:
        flash('The email entered is already in use', 'error')
        return True
    elif username:
        flash('The username entered is already in use', 'error')
        return True
    else:
        print("False")
        return False
        


@app.route('/register', methods=['GET', 'POST'])
def register():
    registration_form = RegistrationForm(request.form)
    email = registration_form.email.data
    username = registration_form.username.data
    if request.method == 'POST' and registration_form.validate() and UsernameEmailInUse(email,username) == False:
        #Initialise User class values

        #Hash password entered
        password = bcrypt.generate_password_hash(registration_form.password.data)

        #Generate OTP Key
        key = pyotp.random_base32()
        
        #Create and add user to DB
        roles = ["user"]
        
        #Create User and place in DB
        new_user = User(email=email, username=username, password=password, roles = roles, otp_secret=key, otp_enabled=False)
        user_data = UserData()
        new_user.user_data = user_data
    
        db.session.add(new_user)
        db.session.commit()

        user_data.user_id = new_user.id
        db.session.add(user_data)

        #Save changes and close session
        db.session.commit()
        db.session.close()

        return redirect(url_for('login'))

    return render_template('register.html', form=registration_form)

@login_manager.user_loader
def load_user(id):
    user = User.query.filter_by(id=id).first()
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():

        username = login_form.username.data

        #Check if user in database
        user = User.query.filter_by(username=func.binary(username)).first()
        
        
        if user:
            password_hash = user.password
            if bcrypt.check_password_hash(password_hash, login_form.password.data):
                if user.otp_enabled == True:
                    #Redirect to page to ask for OTP
                    
                    return redirect(url_for('verify_otp',username=user.username))
                else:
                    #Tell flask principal that identity changed
                    identity_changed.send(app, identity=Identity(user.id))
                    #Get User for database and log in
                    login_user(user)

                    return redirect(url_for('home'))      
            else:
                flash('Invalid Username or Password', 'error') 
                return render_template('login.html', form=login_form)
        else:
            flash('Invalid Username or Password', 'error')  
            return render_template('login.html', form=login_form)

    return render_template('login.html', form=login_form)

@app.route('/login/otp/<username>', methods=['GET', 'POST'])
def verify_otp(username):
    user = User.query.filter_by(username=username).first()
    uri = user.get_totp_uri()
    qrcode.make(uri).save('website/static/totp/totp.png')

    otp_form = OTPForm(request.form)
    if request.method == 'POST' and otp_form.validate():
        otp = otp_form.otp.data
        if user.verify_totp(otp):
            #Tell flask principal that identity changed
            identity_changed.send(app, identity=Identity(user.id))
            #Get User for database and log in
            login_user(user)
            
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP!', 'error')


    return render_template('login_otp.html', form=otp_form)

@app.route('/logout')
@login_required
def logout():
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key,None)

    identity_changed.send(app, identity=AnonymousIdentity())
    logout_user()

    return redirect(url_for('home'))

@app.route('/myprofile', methods=['GET', 'POST'])
@login_required
@user_permission.require(http_exception=403)
def myprofile():
    updateProfileForm = UserDataForm(request.form)
    if request.method == 'POST' and updateProfileForm.validate():
        current_user.user_data.name = updateProfileForm.name.data
        current_user.user_data.phone_no = updateProfileForm.phone.data
        current_user.user_data.address = updateProfileForm.address.data

        db.session.commit()
        
        return redirect(url_for('myprofile'))

    return render_template('myprofile.html', form=updateProfileForm)

@app.route('/enableotp', methods=['GET', 'POST'])
@login_required
@user_permission.require(http_exception=403)
def enable_otp():
    user = User.query.filter_by(username=current_user.username).first()
    uri = user.get_totp_uri()
    qrcode.make(uri).save('website/static/totp/totp.png')
    
    form = OTPForm(request.form)

    if request.method == 'POST' and form.validate():
        otp = form.otp.data
        if user.verify_totp(otp):
            current_user.otp_enabled = True
            db.session.commit()

            return redirect(url_for('myprofile'))

    return render_template('otp.html', form=form)



@app.route('/upload_profile', methods=['POST'])
def upload_profile():
    #hash filename, append postfix
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS'] or \
                file_ext != validate_image(uploaded_file.stream):
            abort(400)
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        
        db.update(UserData).where(UserData.user_id == User.id).values(profile_picture = filename)
        return redirect(url_for('myprofile'))

@app.errorhandler(403)
def page_not_found(e):
    session['redirected_from'] = request.url
    return render_template('forbidden.html')

#========================================================================================

#Royce
#========================================================================================
def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return '.' + (format if format != 'jpeg' else 'jpg')


@app.route('/upload')
def upload():
    return render_template('fileupload.html')


@app.route('/uploader', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def upload_files():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS'] or \
                file_ext != validate_image(uploaded_file.stream):
            abort(400)
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        flash('File uploaded successfully!', 'success')
        return render_template('booking.html', locations=Location.query.all(), uploaded_filename=filename)
    

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        # Generate the path to the file in the 'uploads' folder
        file_path = os.path.join(app.config['UPLOAD_PATH'], filename)

        # Ensure the file exists in the 'uploads' folder
        if os.path.isfile(file_path):
            
            response = make_response(send_file(file_path, as_attachment=True))
            response.headers['Content-Length'] = os.path.getsize(file_path)
            return response
        else:
            flash('File not found.', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        flash('Error occurred while downloading the file.', 'error')
        return redirect(url_for('index'))
    

# Admin Route - Add Location
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def admin():
    if request.method == 'POST':
        name = request.form['location_name']
        price = float(request.form['location_price'])
        new_location = Location(name=name, price=price)
        db.session.add(new_location)
        db.session.commit()
        return redirect(url_for('admin'))

    locations = Location.query.all()
    return render_template('admin.html', locations=locations)


# Admin Booking Page Route
@app.route('/admin/bookings')
@login_required
@admin_permission.require(http_exception=403)
def admin_bookings():
    # Retrieve all bookings from the database
    bookings = Booking.query.all()
    return render_template('admin_bookings.html', bookings=bookings)


@app.route('/booking')
def index():
    # Get all locations from the database
    locations = Location.query.all()

    # Escape location names and descriptions to prevent XSS attacks
    for location in locations:
        location.name = escape(location.name)

    return render_template('booking.html', locations=locations)


@app.route('/location/<int:location_id>/checkout',methods=['GET','POST'])
def checkout(location_id):
    location = Location.query.get(location_id)
    session['location_id'] = location_id

    if request.method == "POST":
        amount = int(location.price)
        customer = stripe.Customer.create(
            email=request.form['stripeEmail'],
            source=request.form['stripeToken']
            )


        stripe.Charge.create(
            customer=customer.id,
            amount=amount*100,
            currency='usd',
            description=location.name +' Ride Charge'
        )

        return redirect(url_for('payment_success'))
    return render_template('checkout.html', location=location)


@app.route('/payment_success')
def payment_success():
    if 'location_id' in session:
        location_id = session['location_id']
        location = Location.query.get(location_id)
        if location:
            
            booking = Booking(location_name=location.name)
            db.session.add(booking)
            db.session.commit()
            session.pop('location_id')
        else:
            flash('Invalid location selected.', 'error')
           
    else:
        flash('Booking data not found.', 'error')

    # Handle successful payment here (e.g., display a success message)
    return render_template('payment_success.html')


#Nicholas
#========================================================================================
def get_data_from_database(country, city):
    # Retrieve eco-friendly activities and descriptions from the combined table
    
    # Separate the results into eco_friendly_activities and descriptions
    eco_friendly_activities = [db.session.query(Eco_Information.activity).filter_by(country=country,city=city).all()]
    descriptions = [db.session.query(Eco_Information.description).filter_by(country=country,city=city).all()]
    images = [db.session.query(Eco_Information.image_url).filter_by(country=country,city=city).all()]

    return eco_friendly_activities, descriptions, images

@app.route('/info')
def info():
    return render_template('info.html')


@app.route('/calculator')
def calculator():
    return render_template('calculator.html')


# Route to handle the search and display the results on the same page
@app.route('/search', methods=['GET', 'POST'])
def search():
    country = None
    city = None
    eco_friendly_activities = None
    descriptions = None
    images = None

    if request.method == 'POST':
        country = bleach.clean(request.form['country'])  # Sanitize input
        city = bleach.clean(request.form['city'])  # Sanitize input

        if len(country) > 100 or len(city) > 100:
            return "Input length exceeded"

        if not re.match(r'^[A-Za-z\s]+$', country) or not re.match(r'^[A-Za-z\s]+$', city):
            return "Invalid input: Please enter only alphabetic characters for country and city."

        # Retrieve data from the database
        eco_friendly_activities, descriptions, images = get_data_from_database(country, city)


    # Pass the data to the template and render it
    return render_template('area.html', country=country, city=city, eco_friendly_activities=eco_friendly_activities, descriptions=descriptions, images=images)




app.app_context().push()
if __name__ == '__main__':
    app.run(debug=True,port='5000',ssl_context=('certs/cert.pem','certs/key.pem'))