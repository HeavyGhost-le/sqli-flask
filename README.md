# 🕵️‍♂️ SQLi Challenge – *"Search & Destroy"*

A beginner-to-intermediate CTF-style Flask web application challenge featuring:

- 🔎 SQL Injection (SQLite)
- 🔐 Login/Register system
- 🧑‍💼 Admin-only flag access
- 🛠️ In-memory database (no persistence)
- 🧪 Realistic layout & UX

---

## 🧩 Challenge Summary

- Users can register and login.
- Logged-in users can search products using a search box.
- The `/search` route is **vulnerable to SQL Injection**:
  ```sql
  ' UNION SELECT 1,username||':'||password||':'||is_admin,3,4 FROM users--

    Goal: Exploit the injection to login as admin or dump the flags table.

🚀 Getting Started
🐍 Requirements

    Python 3.x

    Flask

▶️ Run the App

pip install flask
python app.py

Visit:
📍 http://localhost:5000
🎯 Objective

Your mission:

    🧠 Find and exploit the SQL Injection on /search

    🛂 Access the /admin route (only for logged-in admin users)

    🏁 Retrieve the flag:


⚙️ Technical Details

    Framework: Flask

    DB: SQLite (:memory:)

    Flag is stored in a flags table and viewable only to the admin user

    Login credentials (stored hashed in memory):

        admin / SuperSecureAdminPass123!

        guest / guest_password

🧠 Educational Value

    Practice bypassing authentication

    Understand SQL injection mechanics in SQLite

    Exploit classic search box vulnerabilities

    Learn session hijacking or logic flaws for escalation

⚠️ Disclaimer

This application is intentionally vulnerable and for educational use only.
Do not deploy or expose to the internet.
