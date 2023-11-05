"""Provides all routes for the Social Insecurity application.

This file contains the routes for the application. It is imported by the app package.
It also contains the SQL queries used for communicating with the database.
"""
#Just a test

from pathlib import Path
from app.config import Config
from werkzeug.utils import secure_filename
from flask import flash, redirect, render_template, send_from_directory, url_for
from app import app, sqlite
from app.forms import CommentsForm, FriendsForm, IndexForm, PostForm, ProfileForm
from flask_csp.csp import csp_header

import re
import bcrypt
import time
from flask import session


app.config.from_object(Config)
def escape(t):
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39").replace('"', "&quot;")
    return t

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def sanitize_input(input_str, field):
    # Remove characters that are not allowed in usernames and names
    sanitized_str = re.sub(r"[^a-zA-Z0-9@!$%*?&\s]", "", input_str)

    # Check if any characters were removed and inform the user
    if sanitized_str != input_str:
        flash(f"Some characters in your input were removed due to invalid characters in {field}.", category="warning")
        return False 
    return sanitized_str
#egen local variable
failed_login_attempts = {}


# Define a common function for checking the number of failed login attempts
def check_failed_attempts(username):
    if username in failed_login_attempts:
        attempts, last_attempt_time = failed_login_attempts[username]
        lockout_duration = 300  # Lockout duration in seconds

        if attempts >= 3 and (time.time() - last_attempt_time) < lockout_duration:
            flash("Account temporarily locked due to multiple failed login attempts. Try again later.", category="danger")
            return True

    return False

def is_valid_username(username):
    # Define the criteria for a valid username
    valid_characters = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
    return all(char in valid_characters for char in username)

@app.route("/", methods=["GET", "POST"])
@app.route("/index", methods=["GET", "POST"])
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })

def index():
    index_form = IndexForm()
    login_form = index_form.login
    register_form = index_form.register
    if login_form.is_submitted() and login_form.submit.data:
        username = login_form.username.data

        # Check if the username is timed out due to failed login attempts
        if check_failed_attempts(username):
            return render_template("index.html.j2", title="Welcome", form=index_form)

        # Introduce a small delay to make it harder for attackers
        #time.sleep(2)

        # Use parameterized query to avoid SQL injection
    
        user = sqlite.select_user_by_username(username)
        

        if not login_form.password.data:
            flash("Sorry, failed to log in, NO Pwd entered", category="warning")
            return redirect(url_for("index"))
        

        if user is None:
            flash("Sorry, failed to log in, user NONE", category="warning")
        
            if username in failed_login_attempts:
                attempts, last_attempt_time = failed_login_attempts[username]
                failed_login_attempts[username] = (attempts + 1, time.time())
            else:
                failed_login_attempts[username] = (1, time.time())

        if user != None:
            hashed_password = bcrypt.hashpw(login_form.password.data.encode('utf-8'), user["password"].encode('utf-8')).decode('utf-8')    

            if user["password"] == hashed_password:
                failed_login_attempts.pop(username, None)
                session['username'] = username
                return redirect(url_for("stream", username=session['username']))

        return render_template("index.html.j2", title="Welcome", form=index_form)

    elif register_form.is_submitted() and register_form.submit.data:
        if not is_valid_username(register_form.username.data):
            flash("Invalid username. Usernames can only contain letters, numbers, and underscores.", category="danger")
            return render_template("index.html.j2", title="Welcome", form=index_form)
        # Check if the password meets the strong password criteria
        strong_password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if not re.match(strong_password_pattern, register_form.password.data):
            flash("Password does not meet the strong password criteria. It should contain at least one uppercase letter, one lowercase letter, one digit, one special character (@, $, !, %, *, ?, or &), and be at least 8 characters long.", category="danger")
            return render_template("index.html.j2", title="Welcome", form=index_form)

        hashed_password = bcrypt.hashpw(register_form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Sanitize user input
       
        sanitized_username = sanitize_input(register_form.username.data, 'username')
        sanitized_first_name = sanitize_input(register_form.first_name.data, 'first name')
        sanitized_last_name = sanitize_input(register_form.last_name.data, 'last name')
        
        if sanitized_username is False or sanitized_first_name is False or sanitized_last_name is False:
            flash("User registration failed due to invalid input.", category="danger")
            return render_template("index.html.j2", title="Welcome", form=index_form)

        sqlite.register_user(sanitized_username,sanitized_first_name, sanitized_last_name, hashed_password)

        flash("User successfully created!", category="success")
        return redirect(url_for("index"))


    return render_template("index.html.j2", title="Welcome", form=index_form)


@app.route("/stream/<string:username>", methods=["GET", "POST"])
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })
def stream(username: str):
    """Provides the stream page for the application.

    If a form was submitted, it reads the form data and inserts a new post into the database.

    Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
    """
    post_form = PostForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if post_form.is_submitted():
        if post_form.image.data:
            filename = secure_filename(post_form.image.data.filename)
            if allowed_file(filename):
                path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / filename
                post_form.image.data.save(path)
            else: 
                flash("FILE NOT ALLOWED")
                return redirect(url_for("stream", username=username))
        sanitized_content = escape(post_form.content.data)
        insert_post = f"""
            INSERT INTO Posts (u_id, content, image, creation_time)
            VALUES ({user["id"]}, '{sanitized_content}', '{post_form.image.data.filename}', CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_post)
        return redirect(url_for("stream", username=username))

    get_posts = f"""
         SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
         FROM Posts AS p JOIN Users AS u ON u.id = p.u_id
         WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = {user["id"]}) OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = {user["id"]}) OR p.u_id = {user["id"]}
         ORDER BY p.creation_time DESC;
        """  # noqa: E501
    posts = sqlite.query(get_posts)
    return render_template("stream.html.j2", title="Stream", username=username, form=post_form, posts=posts)


@app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })
def comments(username: str, post_id: int):
    """Provides the comments page for the application.

    If a form was submitted, it reads the form data and inserts a new comment into the database.

    Otherwise, it reads the username and post id from the URL and displays all comments for the post.
    """
    comments_form = CommentsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if comments_form.is_submitted():
        sanitized_content = escape(comments_form.comment.data)
        insert_comment = f"""
            INSERT INTO Comments (p_id, u_id, comment, creation_time)
            VALUES ({post_id}, {user["id"]}, '{sanitized_content}', CURRENT_TIMESTAMP);
            """
        sqlite.query(insert_comment)

    get_post = f"""
        SELECT *
        FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
        WHERE p.id = {post_id};
        """
    get_comments = f"""
        SELECT DISTINCT *
        FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
        WHERE c.p_id={post_id}
        ORDER BY c.creation_time DESC;
        """
    post = sqlite.query(get_post, one=True)
    comments = sqlite.query(get_comments)
    return render_template(
        "comments.html.j2", title="Comments", username=username, form=comments_form, post=post, comments=comments
    )


@app.route("/friends/<string:username>", methods=["GET", "POST"])
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })
def friends(username: str):
    """Provides the friends page for the application.

    If a form was submitted, it reads the form data and inserts a new friend into the database.

    Otherwise, it reads the username from the URL and displays all friends of the user.
    """
    friends_form = FriendsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if friends_form.is_submitted():
        sanitizeds_friend = escape(friends_form.username.data)
        get_friend = f"""
            SELECT *
            FROM Users
            WHERE username = '{sanitizeds_friend}';
            """
        friend = sqlite.query(get_friend, one=True)
        get_friends = f"""
            SELECT f_id
            FROM Friends
            WHERE u_id = {user["id"]};
            """
        friends = sqlite.query(get_friends)

        if friend is None:
            flash("User does not exist!", category="warning")
        elif friend["id"] == user["id"]:
            flash("You cannot be friends with yourself!", category="warning")
        elif friend["id"] in [friend["f_id"] for friend in friends]:
            flash("You are already friends with this user!", category="warning")
        else:
            insert_friend = f"""
                INSERT INTO Friends (u_id, f_id)
                VALUES ({user["id"]}, {friend["id"]});
                """
            sqlite.query(insert_friend)
            flash("Friend successfully added!", category="success")

    get_friends = f"""
        SELECT *
        FROM Friends AS f JOIN Users as u ON f.f_id = u.id
        WHERE f.u_id = {user["id"]} AND f.f_id != {user["id"]};
        """
    friends = sqlite.query(get_friends)
    return render_template("friends.html.j2", title="Friends", username=username, friends=friends, form=friends_form)


@app.route("/profile/<string:username>", methods=["GET", "POST"])
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })
def profile(username: str):
    """Provides the profile page for the application.

    If a form was submitted, it reads the form data and updates the user's profile in the database.

    Otherwise, it reads the username from the URL and displays the user's profile.
    """
    profile_form = ProfileForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if profile_form.is_submitted():
        sanitized_education = escape(profile_form.education.data)
        sanitized_employment =  escape(profile_form.employment.data)
        sanitized_music = escape(profile_form.music.data)
        sanitized_movie = escape(profile_form.movie.data)
        sanitized_nationality = escape(profile_form.nationality.data)
        sanitized_birthday = escape(profile_form.birthday.data)

        update_profile = f"""
            UPDATE Users
            SET education='{sanitized_education}', employment='{sanitized_employment}',
                music='{sanitized_music}', movie='{sanitized_movie}',
                nationality='{sanitized_nationality}', birthday='{sanitized_birthday}'
            WHERE username='{username}';
            """
        sqlite.query(update_profile)
        return redirect(url_for("profile", username=username))

    return render_template("profile.html.j2", title="Profile", username=username, user=user, form=profile_form)


@app.route("/uploads/<string:filename>")
@csp_header({'default-src':"'self'",'script-src':"'self' https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js ", 'style-src-elem': "'self' https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css " })
def uploads(filename):
    """Provides an endpoint for serving uploaded files."""
    return send_from_directory(Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"], filename)
