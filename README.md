# We Got You

A mental-wellness web app built with Flask. **We Got You** brings together curated mental-health reading, a place to connect with friends and professionals, a personal tracker, and simple games, all behind a lightweight user account system.

> Built as a hackathon project. The Tracker section is a scaffolded page that is ready to be extended.

## Features

- **Blog Posts:** a responsive image grid linking to mental-health resources from the WHO and NIMH (the home page).
- **Connect:** a gallery of friends and professionals to reach out to.
- **Tracker:** a login-protected page for tracking your mental health.
- **Games:** relaxing in-browser puzzles: a wellness-themed mini crossword (check, reveal, clear) and a randomly generated Sudoku that highlights conflicting numbers.
- **User accounts:** register, log in, log out and change your password. Passwords are stored as salted hashes (Werkzeug) and sessions are stored server-side.
- **Friendly errors:** invalid input renders a meme-style apology page.

## Tech Stack

| Layer      | Technology                                    |
|------------|-----------------------------------------------|
| Backend    | Python 3.11, Flask, Flask-Session             |
| Database   | SQLite (via the CS50 `SQL` library)           |
| Frontend   | Jinja2 templates, Bootstrap 5.3, custom CSS, vanilla JavaScript |
| Auth       | Werkzeug password hashing, server-side sessions |
| Production | Gunicorn                                      |

## Project Structure

```
we-got-you/
├── app.py              # Flask app: routes, auth, DB setup
├── helpers.py          # apology() error page and @login_required decorator
├── schema.sql          # SQLite schema, applied automatically on startup
├── requirements.txt    # Python dependencies
├── .python-version     # Python version used for deployment
├── static/
│   ├── styles.css      # Custom styles
│   ├── games.js        # Crossword and Sudoku logic (vanilla JS)
│   ├── favicon.ico     # Site icon / logo
│   ├── we-got-you.ico  # Wordmark logo
│   └── images/         # Blog and Connect grid images
└── templates/
    ├── layout.html     # Base layout (navbar, flash messages, footer)
    ├── blogpost.html   # Home / Blog Posts
    ├── connect.html
    ├── tracker.html
    ├── game.html
    ├── login.html
    ├── register.html
    ├── change.html     # Change password
    └── apology.html    # Error page
```

## Running Locally

**Prerequisites:** Python 3.11+

```bash
# 1. Clone the repository
git clone https://github.com/kritikarunam30/we-got-you.git
cd we-got-you

# 2. Create and activate a virtual environment
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
flask run
```

Then open http://127.0.0.1:5000.

On the first run the app creates `user.db` from `schema.sql`. Session data is written to `flask_session/`. Both are generated at runtime and are git-ignored.

### Production server

```bash
gunicorn app:app
```

(Gunicorn runs on Linux/macOS. On Windows, use `flask run` for local development.)

## Configuration

No environment variables or API keys are required. The app runs out of the box.

| Setting         | Where       | Default                          |
|-----------------|-------------|----------------------------------|
| Database        | `app.py`    | `user.db` (SQLite, auto-created) |
| Session storage | `app.py`    | Filesystem (`flask_session/`)    |

## Routes

| Route       | Method    | Auth required | Description            |
|-------------|-----------|:-------------:|------------------------|
| `/`         | GET       |               | Redirects to `/blogpost` |
| `/blogpost` | GET       |               | Blog posts grid        |
| `/connect`  | GET       |               | Connect gallery        |
| `/tracker`  | GET, POST | ✓             | Mental-health tracker  |
| `/game`     | GET       |               | Games                  |
| `/register` | GET, POST |               | Create an account      |
| `/login`    | GET, POST |               | Log in                 |
| `/logout`   | GET       |               | Log out                |
| `/change`   | GET, POST | ✓             | Change password        |

## Deployment

The app is deployment-ready for any platform that runs a persistent Python process (for example [Render](https://render.com)):

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app`

Note: SQLite and filesystem sessions live on the server's disk. On free tiers with ephemeral storage, user accounts reset whenever the service restarts or redeploys.
