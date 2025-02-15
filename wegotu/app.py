import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///user.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show Blogpost"""
    # Redirect user to blogpost page
    return redirect("/blogpost")


@app.route("/blogpost", methods=["GET"])
def blogpost():
    """Display BlogPost"""
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("blogpost.html")

@app.route("/connect", methods=["GET"])
def connect():
    """Display Connect Page"""
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("connect.html")

@app.route("/tracker", methods=["GET", "POST"])
@login_required
def tracker():
    """Display Tracker Page"""
    # Remember which user has logged in
    user_id = session["user_id"]

    # User reached route via POST (by being looged in or logging in)
    if request.method == "POST":
        #Show History and ask questions

    if request.method == "GET":
        # User reached route via GET (as by clicking a link or via redirect)
        return render_template("tracker.html")

@app.route("/game", methods=["GET"])
def game():
    """Display Animal Crossing Game"""
    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("game.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)
        print(rows)  # Debugging: print the query result

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # Ensure confirmation password was submitted
        if not request.form.get("confirmation"):
            return apology("must provide confirmation password")

        # Ensure confirmation and password are same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")
        # Create hash
        hash = generate_password_hash(request.form.get("password"))

        # Check if username already exists in database
        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?,?)",
                                  request.form.get("username"), hash)
            # Remember which user has logged in
            session["user_id"] = new_user

            # Redirect user to home page
            return redirect("/")

        except:
            return apology("username already exists")
    else:
        return render_template("register.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Allow user to change password."""
    # User reached route via POST (as by submitting a form via POST)
    user_id = session["user_id"]
    if request.method == "POST":
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password")

        # Ensure confirmation password was submitted
        if not request.form.get("confirmation"):
            return apology("must provide confirmation password")

        # Ensure confirmation and password are same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")
        # Create hash
        new_hash = generate_password_hash(request.form.get("password"))

        # Update Table
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        flash("Password has been changed.")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking)
    else:
        return render_template("change.html")
