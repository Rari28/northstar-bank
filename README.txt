NORTHSTAR BANK - SCHOOL PROJECT STARTER

1. Install Python 3.
2. Open a terminal in this project folder.
3. Run: pip install -r requirements.txt
4. Run: python app.py
5. Open http://127.0.0.1:5000 in your browser.

DEFAULT ADMIN LOGIN
Username: admin
PIN: 1234

Admin creates customer accounts from the admin dashboard.
Customers log in using the username and PIN assigned by the admin.

The SQLite database file (banking.db) is created automatically when the app starts.
This is a simulated school project, not a real banking service.

Before deployment:
- Set a strong SECRET_KEY environment variable.
- Turn debug mode off.
- Use HTTPS and a production WSGI server.
- Add CSRF protection, rate limiting, stronger account recovery, and backups.
- Never use real customer banking information.
