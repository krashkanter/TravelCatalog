import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, flash, abort, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from functools import wraps
from datetime import datetime
import click

basedir = os.path.abspath(os.path.dirname(__file__))
sql_dir = os.path.join(basedir, 'sql')
os.makedirs(sql_dir, exist_ok=True)
db_path = os.path.join(sql_dir, 'db.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_secure_key'


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


login_manager = LoginManager(app)
login_manager.login_view = 'login'


# --- Database Connection and Management ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # Return rows as dictionary-like objects for easier access by column name
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with the schema."""
    db = get_db()
    with app.open_resource('sql/schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    # Add a default admin user if none exists (optional, but useful for initial setup)
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    if admin_count == 0:
        # You might want to prompt for admin details or read from env vars in a real app
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'adminpassword')  # **CHANGE THIS IN PRODUCTION**
        hashed_password = generate_password_hash(admin_password)
        try:
            cursor.execute("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                           ('Admin User', admin_email, hashed_password, 'admin'))
            db.commit()
            print(f"Default admin user created: {admin_email}")
        except sqlite3.IntegrityError:
            print(f"Admin user creation skipped: {admin_email} already exists")


@app.cli.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')


# Register the close_db function with the app context
app.teardown_appcontext(close_db)


# --- User Model (Simplified for LoginManager, no longer ORM) ---
class User(UserMixin):
    def __init__(self, id, name, email, password_hash, role):
        self.id = id
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.role = role

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, plaintext):
        # Note: This setter updates the object's attribute, not the database.
        # Database update happens via explicit SQL INSERT/UPDATE.
        self.password_hash = generate_password_hash(plaintext)

    def verify_password(self, plaintext):
        return check_password_hash(self.password_hash, plaintext)


# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, email, password_hash, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        # Create a User object from the fetched data
        return User(id=user_data['id'], name=user_data['name'],
                    email=user_data['email'], password_hash=user_data['password_hash'],
                    role=user_data['role'])
    return None


# --- Forms (Stay largely the same, but validation might use raw SQL) ---
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Register')

    def validate_email(self, field):
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM users WHERE email = ?", (field.data,))
        if cursor.fetchone():
            raise ValidationError('Email already in use.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class DistrictForm(FlaskForm):
    name = StringField('District Name', validators=[DataRequired()])
    image_url = StringField('Image URL')
    submit = SubmitField('Save')


class TalukForm(FlaskForm):
    name = StringField('Taluk Name', validators=[DataRequired()])
    # Choices will be populated dynamically from DB in the route
    district_id = SelectField('District', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save')


class DestinationForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    desc = TextAreaField('Description')
    image_url = StringField('Image URL')
    submit = SubmitField('Save')


class FoodForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    desc = TextAreaField('Description')
    image_url = StringField('Image URL')
    submit = SubmitField('Save')


class AccommodationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    details = TextAreaField('Details')
    image_url = StringField('Image URL')
    submit = SubmitField('Save')


class ExperienceForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    desc = TextAreaField('Description')
    image_url = StringField('Image URL')
    submit = SubmitField('Save')


class CommentForm(FlaskForm):
    category = SelectField('Category', choices=[('destination', 'Destination'), ('food', 'Food'),
                                                ('accommodation', 'Accommodation'), ('experience', 'Experience')],
                           validators=[DataRequired()])
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')


# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or (hasattr(current_user, 'role') and current_user.role != 'admin'):
            abort(403)
        return f(*args, **kwargs)

    return decorated


# --- User Routes (Now using raw SQL) ---
@app.route('/')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()

    # 1. Fetch all districts
    cursor.execute("SELECT id, name, image_url FROM districts")
    district_rows = cursor.fetchall()  # These are sqlite3.Row objects

    # 2. Fetch all taluks
    # Ordering by district_id can be helpful for the grouping step
    cursor.execute("SELECT id, name, district_id FROM taluks ORDER BY district_id")
    taluk_rows = cursor.fetchall()  # These are sqlite3.Row objects

    # 3. Organize taluks by district_id in a dictionary
    taluks_by_district = {}
    for taluk in taluk_rows:
        district_id = taluk['district_id']
        if district_id not in taluks_by_district:
            taluks_by_district[district_id] = []
        taluks_by_district[district_id].append(taluk)

    # 4. Create a new list of districts, adding their associated taluks
    districts_with_taluks = []
    for district in district_rows:
        # Convert the sqlite3.Row (read-only) to a mutable dictionary
        district_data = dict(district)
        # Get the list of taluks for this district (or an empty list)
        district_data['taluks'] = taluks_by_district.get(district_data['id'], [])
        districts_with_taluks.append(district_data)

    # 5. Pass the enhanced list to the template
    return render_template('dashboard.html', districts=districts_with_taluks)


@app.route('/district/<int:district_id>')
@login_required
def view_district(district_id):
    db = get_db()
    cursor = db.cursor()

    # Fetch the specific district
    cursor.execute("SELECT id, name, image_url FROM districts WHERE id = ?", (district_id,))
    district_row = cursor.fetchone()

    if district_row is None:
        abort(404)

    district_data = dict(district_row)  # Convert row to dict

    # --- FIX: Fetch taluks for this district, including counts ---
    cursor.execute("""
                   SELECT t.id,
                          t.name,
                          t.district_id,
                          COUNT(DISTINCT dest.id) AS destination_count,
                          COUNT(DISTINCT f.id)    AS food_count,
                          COUNT(DISTINCT acc.id)  AS accommodation_count,
                          COUNT(DISTINCT exp.id)  AS experience_count
                   FROM taluks t
                            LEFT JOIN destinations dest ON t.id = dest.taluk_id
                            LEFT JOIN food f ON t.id = f.taluk_id
                            LEFT JOIN accommodation acc ON t.id = acc.taluk_id
                            LEFT JOIN experiences exp ON t.id = exp.taluk_id
                   WHERE t.district_id = ? -- Filter by the current district
                   GROUP BY t.id, t.name, t.district_id -- Group by taluk
                   ORDER BY t.name; -- Optional: order taluks by name
                   """, (district_data['id'],))  # Use the district's ID
    taluks_list = cursor.fetchall()  # Fetch taluks with counts

    district_data['taluks'] = taluks_list  # Add the list of taluks with counts

    # Pass the single, enhanced district dictionary to the template
    # The variable name is still 'district' for template compatibility
    return render_template('district.html', district=district_data)


@app.route('/taluk/<int:taluk_id>', methods=['GET', 'POST'])
@login_required
def view_taluk(taluk_id):
    db = get_db()
    cursor = db.cursor()

    # Fetch the taluk
    # Using JOIN here to get district name directly for potential use in template/breadcrumbs
    cursor.execute("""
                   SELECT t.id, t.name, t.district_id, d.name AS district_name
                   FROM taluks t
                            JOIN districts d ON t.district_id = d.id
                   WHERE t.id = ?
                   """, (taluk_id,))
    taluk_row = cursor.fetchone()  # Get the single taluk row

    # If taluk not found, return 404
    if taluk_row is None:
        abort(404)

    # Convert the sqlite3.Row object to a mutable dictionary
    taluk_data = dict(taluk_row)

    form = CommentForm()
    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO comments (user_id, taluk_id, category, content) VALUES (?, ?, ?, ?)",
                (current_user.id, taluk_data['id'], form.category.data, form.content.data)
            )
            db.commit()
            flash('Comment posted.', 'success')
            # Redirect after POST to prevent form resubmission
            return redirect(url_for('view_taluk', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error posting comment: {e}', 'danger')
        # Note: If validation fails, the form will be rendered below with errors.

    # Fetch related data for the taluk (Destinations, Food, Accommodation, Experiences)
    # These are fetched as lists of sqlite3.Row objects and passed directly
    cursor.execute("SELECT id, title, desc, image_url FROM destinations WHERE taluk_id = ?", (taluk_data['id'],))
    destinations = cursor.fetchall()

    cursor.execute("SELECT id, name, desc, image_url FROM food WHERE taluk_id = ?", (taluk_data['id'],))
    food_items = cursor.fetchall()

    cursor.execute("SELECT id, name, details, image_url FROM accommodation WHERE taluk_id = ?", (taluk_data['id'],))
    accommodations = cursor.fetchall()

    cursor.execute("SELECT id, name, desc, image_url FROM experiences WHERE taluk_id = ?", (taluk_data['id'],))
    experiences = cursor.fetchall()

    # --- Fetch Comments and Format Timestamps ---
    cursor.execute("""
                   SELECT c.id,
                          c.content,
                          c.timestamp,
                          c.category,
                          u.name AS author_name
                   FROM comments c
                            JOIN users u ON c.user_id = u.id
                   WHERE c.taluk_id = ?
                   ORDER BY c.timestamp DESC -- Order by timestamp, latest first
                   """, (taluk_data['id'],))
    comment_rows = cursor.fetchall()  # Fetch sqlite3.Row objects

    # Format the timestamp for each comment before sending to template
    formatted_comments = []
    for comment_row in comment_rows:
        # Convert the row to a dictionary to make it mutable and add keys
        comment_data = dict(comment_row)

        # Get the timestamp value (which is likely a string from SQLite)
        timestamp_value = comment_data.get('timestamp')  # Use .get for safety

        # Attempt to parse the string into a datetime object and format it
        # The default format for CURRENT_TIMESTAMP in SQLite is often 'YYYY-MM-DD HH:MM:SS'
        formatted_ts = str(timestamp_value) if timestamp_value is not None else ''  # Default value
        if isinstance(timestamp_value, str):
            try:
                # Parse the string according to the expected format from SQLite
                # Use a format that matches SQLite's CURRENT_TIMESTAMP output
                dt_object = datetime.strptime(timestamp_value, '%Y-%m-%d %H:%M:%S')
                # Format the datetime object into the desired display string
                formatted_ts = dt_object.strftime('%Y-%m-%d %H:%M')
            except (ValueError, TypeError):
                # If parsing fails, just keep the original string representation
                print(f"Warning: Could not parse timestamp string: {timestamp_value}")
                pass  # formatted_ts remains the original string or default

        # Add the formatted timestamp to the dictionary
        comment_data['formatted_timestamp'] = formatted_ts

        formatted_comments.append(comment_data)
    # --- End Fetch Comments and Format Timestamps ---

    # Pass all collected data to the template
    # 'taluk' variable is now the dictionary including district_name
    # 'comments' variable is the list of dictionaries with formatted timestamps
    return render_template('taluk.html',
                           taluk=taluk_data,  # Pass the taluk dictionary
                           destinations=destinations,
                           food_items=food_items,
                           accommodations=accommodations,
                           experiences=experiences,
                           comments=formatted_comments,  # Pass the list with formatted timestamps
                           form=form)  # Pass the comment form


# --- Authentication (Now using raw SQL) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        db = get_db()
        cursor = db.cursor()
        # Password hashing is done manually
        hashed_password = generate_password_hash(form.password.data)
        try:
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (form.name.data, form.email.data, hashed_password, 'user')
            )
            db.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            db.rollback()  # Rollback the transaction on error
            flash('Email already in use.', 'danger')
        except sqlite3.Error as e:
            db.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db = get_db()
        cursor = db.cursor()
        # Fetch user by email
        cursor.execute("SELECT id, name, email, password_hash, role FROM users WHERE email = ?", (form.email.data,))
        user_data = cursor.fetchone()  # Fetch a single user

        if user_data:
            # Create a User object and verify password manually
            user = User(id=user_data['id'], name=user_data['name'],
                        email=user_data['email'], password_hash=user_data['password_hash'],
                        role=user_data['role'])
            if user.verify_password(form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        else:
            flash('Invalid email or password.', 'danger')  # User not found

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- Admin Routes (Now using raw SQL) ---
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')


# District CRUD
@app.route('/admin/districts')
@login_required
@admin_required
def list_districts():
    db = get_db()
    cursor = db.cursor()

    # 1. Fetch all districts
    cursor.execute("SELECT id, name, image_url FROM districts")
    district_rows = cursor.fetchall()  # These are sqlite3.Row objects

    # 2. Fetch all taluks
    cursor.execute("SELECT id, name, district_id FROM taluks ORDER BY district_id")
    taluk_rows = cursor.fetchall()  # These are sqlite3.Row objects

    # 3. Organize taluks by district_id in a dictionary
    taluks_by_district = {}
    for taluk in taluk_rows:
        district_id = taluk['district_id']
        if district_id not in taluks_by_district:
            taluks_by_district[district_id] = []
        taluks_by_district[district_id].append(taluk)

    # 4. Create a new list of districts, adding their associated taluks
    districts_with_taluks = []
    for district in district_rows:
        # Convert the sqlite3.Row (read-only) to a mutable dictionary
        district_data = dict(district)
        # Get the list of taluks for this district (or an empty list)
        district_data['taluks'] = taluks_by_district.get(district_data['id'], [])
        districts_with_taluks.append(district_data)

    # 5. Pass the enhanced list to the template
    return render_template('admin/districts.html', districts=districts_with_taluks)


@app.route('/admin/districts/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_district():
    form = DistrictForm()
    if form.validate_on_submit():
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO districts (name, image_url) VALUES (?, ?)",
                (form.name.data, form.image_url.data or None)  # Use None for empty image_url
            )
            db.commit()
            flash('District added.', 'success')
            return redirect(url_for('list_districts'))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding district: {e}', 'danger')
    return render_template('admin/add_district.html', form=form)


@app.route('/admin/districts/<int:district_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_district(district_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, image_url FROM districts WHERE id = ?", (district_id,))
    district = cursor.fetchone()
    if district is None:
        abort(404)

    form = DistrictForm(data=district)  # Populate form with data from the row
    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE districts SET name = ?, image_url = ? WHERE id = ?",
                (form.name.data, form.image_url.data or None, district_id)
            )
            db.commit()
            flash('District updated.', 'success')
            return redirect(url_for('list_districts'))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating district: {e}', 'danger')

    return render_template('admin/edit_district.html', form=form, district=district)


@app.route('/admin/districts/<int:district_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_district(district_id):
    db = get_db()
    cursor = db.cursor()
    try:
        # Deletion in Taluks will cascade due to FOREIGN KEY constraint in schema.sql
        cursor.execute("DELETE FROM districts WHERE id = ?", (district_id,))
        db.commit()
        flash('District deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting district: {e}', 'danger')
    return redirect(url_for('list_districts'))


# Taluk CRUD
# Taluk CRUD
@app.route('/admin/taluks')
@login_required
@admin_required
def list_taluks():
    db = get_db()
    cursor = db.cursor()
    # Join with districts and LEFT JOIN with related tables to get counts
    cursor.execute("""
                   SELECT t.id,
                          t.name,
                          d.name                  AS district_name,
                          COUNT(DISTINCT dest.id) AS destination_count,
                          COUNT(DISTINCT f.id)    AS food_count,
                          COUNT(DISTINCT acc.id)  AS accommodation_count,
                          COUNT(DISTINCT exp.id)  AS experience_count
                   FROM taluks t
                            JOIN
                        districts d ON t.district_id = d.id
                            LEFT JOIN -- Use LEFT JOIN to include taluks even if they have no destinations
                       destinations dest ON t.id = dest.taluk_id
                            LEFT JOIN -- Use LEFT JOIN to include taluks even if they have no food
                       food f ON t.id = f.taluk_id
                            LEFT JOIN -- Use LEFT JOIN to include taluks even if they have no accommodation
                       accommodation acc ON t.id = acc.taluk_id
                            LEFT JOIN -- Use LEFT JOIN to include taluks even if they have no experiences
                       experiences exp ON t.id = exp.taluk_id
                   GROUP BY -- Group by taluk and district details to get counts per taluk
                            t.id, t.name, d.name
                   ORDER BY d.name, t.name; -- Optional: order by district then taluk name
                   """)
    # The returned 'taluks' will now be a list of sqlite3.Row objects
    # each containing id, name, district_name, destination_count, food_count, accommodation_count, experience_count
    taluks = cursor.fetchall()
    return render_template('admin/taluks.html', taluks=taluks)


@app.route('/admin/taluks/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_taluk():
    db = get_db()
    cursor = db.cursor()
    form = TalukForm()

    # Populate the district choices for the select field
    cursor.execute("SELECT id, name FROM districts ORDER BY name")
    form.district_id.choices = [(d['id'], d['name']) for d in cursor.fetchall()]

    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO taluks (name, district_id) VALUES (?, ?)",
                (form.name.data, form.district_id.data)
            )
            db.commit()
            flash('Taluk added.', 'success')
            return redirect(url_for('list_taluks'))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding taluk: {e}', 'danger')
    return render_template('admin/add_taluk.html', form=form)


@app.route('/admin/taluks/<int:taluk_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_taluk(taluk_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, district_id FROM taluks WHERE id = ?", (taluk_id,))
    taluk = cursor.fetchone()
    if taluk is None:
        abort(404)

    form = TalukForm(data=taluk)  # Populate form with data

    # Populate district choices
    cursor.execute("SELECT id, name FROM districts ORDER BY name")
    form.district_id.choices = [(d['id'], d['name']) for d in cursor.fetchall()]

    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE taluks SET name = ?, district_id = ? WHERE id = ?",
                (form.name.data, form.district_id.data, taluk_id)
            )
            db.commit()
            flash('Taluk updated.', 'success')
            return redirect(url_for('list_taluks'))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating taluk: {e}', 'danger')

    return render_template('admin/edit_taluk.html', form=form, taluk=taluk)


@app.route('/admin/taluks/<int:taluk_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_taluk(taluk_id):
    db = get_db()
    cursor = db.cursor()
    try:
        # Deletions in Destinations, Food, etc. will cascade
        cursor.execute("DELETE FROM taluks WHERE id = ?", (taluk_id,))
        db.commit()
        flash('Taluk deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting taluk: {e}', 'danger')
    return redirect(url_for('list_taluks'))


# Destination CRUD
@app.route('/admin/taluks/<int:taluk_id>/destinations')
@login_required
@admin_required
def list_destinations(taluk_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk = cursor.fetchone()
    if taluk is None:
        abort(404)

    cursor.execute("SELECT id, title, desc, image_url FROM destinations WHERE taluk_id = ?", (taluk_id,))
    destinations = cursor.fetchall()
    return render_template('admin/destinations.html', taluk=taluk, destinations=destinations)


@app.route('/admin/taluks/<int:taluk_id>/destinations/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_destination(taluk_id):
    db = get_db()
    cursor = db.cursor()
    # Check if taluk exists
    cursor.execute("SELECT id FROM taluks WHERE id = ?", (taluk_id,))
    if cursor.fetchone() is None:
        abort(404)

    form = DestinationForm()
    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO destinations (title, desc, image_url, taluk_id) VALUES (?, ?, ?, ?)",
                (form.title.data, form.desc.data, form.image_url.data or None, taluk_id)
            )
            db.commit()
            flash('Destination added.', 'success')
            return redirect(url_for('list_destinations', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding destination: {e}', 'danger')
    return render_template('admin/add_destination.html', form=form, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/destinations/<int:dest_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_destination(taluk_id, dest_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, title, desc, image_url, taluk_id FROM destinations WHERE id = ? AND taluk_id = ?",
                   (dest_id, taluk_id))
    dest = cursor.fetchone()
    if dest is None:
        abort(404)

    form = DestinationForm(data=dest)
    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE destinations SET title = ?, desc = ?, image_url = ? WHERE id = ?",
                (form.title.data, form.desc.data, form.image_url.data or None, dest_id)
            )
            db.commit()
            flash('Destination updated.', 'success')
            return redirect(url_for('list_destinations', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating destination: {e}', 'danger')
    return render_template('admin/edit_destination.html', form=form, destination=dest, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/destinations/<int:dest_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_destination(taluk_id, dest_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM destinations WHERE id = ? AND taluk_id = ?", (dest_id, taluk_id))
        db.commit()
        # Check if a row was actually deleted
        if cursor.rowcount == 0:
            flash('Destination not found or does not belong to this taluk.', 'warning')
        else:
            flash('Destination deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting destination: {e}', 'danger')
    return redirect(url_for('list_destinations', taluk_id=taluk_id))


# Food CRUD (Pattern is similar to Destinations)
@app.route('/admin/taluks/<int:taluk_id>/food')
@login_required
@admin_required
def list_food(taluk_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk = cursor.fetchone()
    if taluk is None:
        abort(404)

    cursor.execute("SELECT id, name, desc, image_url FROM food WHERE taluk_id = ?", (taluk_id,))
    food_items = cursor.fetchall()
    return render_template('admin/food.html', taluk=taluk, food_items=food_items)


@app.route('/admin/taluks/<int:taluk_id>/food/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_food(taluk_id):
    db = get_db()
    cursor = db.cursor()
    # Check if taluk exists
    cursor.execute("SELECT id FROM taluks WHERE id = ?", (taluk_id,))
    if cursor.fetchone() is None:
        abort(404)

    form = FoodForm()
    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO food (name, desc, image_url, taluk_id) VALUES (?, ?, ?, ?)",
                (form.name.data, form.desc.data, form.image_url.data or None, taluk_id)
            )
            db.commit()
            flash('Food item added.', 'success')
            return redirect(url_for('list_food', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding food item: {e}', 'danger')
    return render_template('admin/add_food.html', form=form, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/food/<int:food_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_food(taluk_id, food_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, desc, image_url, taluk_id FROM food WHERE id = ? AND taluk_id = ?",
                   (food_id, taluk_id))
    food = cursor.fetchone()
    if food is None:
        abort(404)

    form = FoodForm(data=food)
    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE food SET name = ?, desc = ?, image_url = ? WHERE id = ?",
                (form.name.data, form.desc.data, form.image_url.data or None, food_id)
            )
            db.commit()
            flash('Food updated.', 'success')
            return redirect(url_for('list_food', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating food: {e}', 'danger')
    return render_template('admin/edit_food.html', form=form, food=food, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/food/<int:food_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_food(taluk_id, food_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM food WHERE id = ? AND taluk_id = ?", (food_id, taluk_id))
        db.commit()
        if cursor.rowcount == 0:
            flash('Food item not found or does not belong to this taluk.', 'warning')
        else:
            flash('Food item deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting food item: {e}', 'danger')
    return redirect(url_for('list_food', taluk_id=taluk_id))


# Accommodation CRUD (Pattern is similar)
@app.route('/admin/taluks/<int:taluk_id>/accommodations')
@login_required
@admin_required
def list_accommodations(taluk_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk = cursor.fetchone()
    if taluk is None:
        abort(404)

    cursor.execute("SELECT id, name, details, image_url FROM accommodation WHERE taluk_id = ?", (taluk_id,))
    accommodations = cursor.fetchall()
    return render_template('admin/accommodations.html', taluk=taluk, accommodations=accommodations)


@app.route('/admin/taluks/<int:taluk_id>/accommodations/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_accommodation(taluk_id):
    db = get_db()
    cursor = db.cursor()

    # --- FIX: Fetch taluk details for the template ---
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk_data = cursor.fetchone()  # Fetch the taluk data

    if taluk_data is None:
        abort(404)  # Abort if taluk doesn't exist

    form = AccommodationForm()

    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO accommodation (name, details, image_url, taluk_id) VALUES (?, ?, ?, ?)",
                (form.name.data, form.details.data, form.image_url.data or None, taluk_id)
            )
            db.commit()
            flash('Accommodation added.', 'success')
            return redirect(url_for('list_accommodations', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding accommodation: {e}', 'danger')
            # If validation fails or DB error occurs, re-render the page with the form and taluk data

    # --- FIX: Pass taluk_data to render_template as 'taluk' ---
    return render_template('admin/add_accommodation.html', form=form, taluk=taluk_data)


@app.route('/admin/taluks/<int:taluk_id>/accommodations/<int:acc_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_accommodation(taluk_id, acc_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, details, image_url, taluk_id FROM accommodation WHERE id = ? AND taluk_id = ?",
                   (acc_id, taluk_id))
    acc = cursor.fetchone()
    if acc is None:
        abort(404)

    form = AccommodationForm(data=acc)
    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE accommodation SET name = ?, details = ?, image_url = ? WHERE id = ?",
                (form.name.data, form.details.data, form.image_url.data or None, acc_id)
            )
            db.commit()
            flash('Accommodation updated.', 'success')
            return redirect(url_for('list_accommodations', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating accommodation: {e}', 'danger')
    return render_template('admin/edit_accommodation.html', form=form, accommodation=acc, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/accommodations/<int:acc_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_accommodation(taluk_id, acc_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM accommodation WHERE id = ? AND taluk_id = ?", (acc_id, taluk_id))
        db.commit()
        if cursor.rowcount == 0:
            flash('Accommodation not found or does not belong to this taluk.', 'warning')
        else:
            flash('Accommodation deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting accommodation: {e}', 'danger')
    return redirect(url_for('list_accommodations', taluk_id=taluk_id))


# Experience CRUD (Pattern is similar)
@app.route('/admin/taluks/<int:taluk_id>/experiences')
@login_required
@admin_required
def list_experiences(taluk_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk = cursor.fetchone()
    if taluk is None:
        abort(404)

    cursor.execute("SELECT id, name, desc, image_url FROM experiences WHERE taluk_id = ?", (taluk_id,))
    experiences = cursor.fetchall()
    return render_template('admin/experiences.html', taluk=taluk, experiences=experiences)


@app.route('/admin/taluks/<int:taluk_id>/experiences/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_experience(taluk_id):
    db = get_db()
    cursor = db.cursor()

    # --- FIX: Fetch taluk details for the template ---
    cursor.execute("SELECT id, name FROM taluks WHERE id = ?", (taluk_id,))
    taluk_data = cursor.fetchone()  # Fetch the taluk data

    if taluk_data is None:
        abort(404)  # Abort if taluk doesn't exist

    form = ExperienceForm()

    if form.validate_on_submit():
        try:
            cursor.execute(
                "INSERT INTO experiences (name, desc, image_url, taluk_id) VALUES (?, ?, ?, ?)",
                (form.name.data, form.desc.data, form.image_url.data or None, taluk_id)
            )
            db.commit()
            flash('Experience added.', 'success')
            return redirect(url_for('list_experiences', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error adding experience: {e}', 'danger')
            # If validation fails or DB error occurs, re-render the page with the form and taluk data

    # --- FIX: Pass taluk_data to render_template as 'taluk' ---
    return render_template('admin/add_experience.html', form=form, taluk=taluk_data)


@app.route('/admin/taluks/<int:taluk_id>/experiences/<int:exp_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_experience(taluk_id, exp_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, name, desc, image_url, taluk_id FROM experiences WHERE id = ? AND taluk_id = ?",
                   (exp_id, taluk_id))
    exp = cursor.fetchone()
    if exp is None:
        abort(404)

    form = ExperienceForm(data=exp)
    if form.validate_on_submit():
        try:
            cursor.execute(
                "UPDATE experiences SET name = ?, desc = ?, image_url = ? WHERE id = ?",
                (form.name.data, form.desc.data, form.image_url.data or None, exp_id)
            )
            db.commit()
            flash('Experience updated.', 'success')
            return redirect(url_for('list_experiences', taluk_id=taluk_id))
        except sqlite3.Error as e:
            db.rollback()
            flash(f'Error updating experience: {e}', 'danger')
    return render_template('admin/edit_experience.html', form=form, experience=exp, taluk_id=taluk_id)


@app.route('/admin/taluks/<int:taluk_id>/experiences/<int:exp_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_experience(taluk_id, exp_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM experiences WHERE id = ? AND taluk_id = ?", (exp_id, taluk_id))
        db.commit()
        if cursor.rowcount == 0:
            flash('Experience not found or does not belong to this taluk.', 'warning')
        else:
            flash('Experience deleted.', 'success')
    except sqlite3.Error as e:
        db.rollback()
        flash(f'Error deleting experience: {e}', 'danger')
    return redirect(url_for('list_experiences', taluk_id=taluk_id))


if __name__ == '__main__':
    app.run(debug=True)
