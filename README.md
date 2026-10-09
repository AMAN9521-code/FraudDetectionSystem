# RADAR: AI-Powered Fraud Detection System

**Detect. Analyze. Prevent.**

RADAR (Risk Analysis and Detection of Anonymous Response) is a Java web application that monitors financial transactions, calculates a risk score for each one, flags suspicious activity, and lets administrators review alerts and tune the detection rules. The system learns from admin feedback by adjusting rule weights over time.

**Live demo:** https://frauddetectionsystem-production-3ecc.up.railway.app/
*(Hosted on a Railway trial plan, so the link may stop working. If it is down, use the local setup below.)*

---

## Table of Contents

1. [Features](#features)
2. [How Fraud Detection Works](#how-fraud-detection-works)
3. [Technology Stack](#technology-stack)
4. [Project Structure](#project-structure)
5. [Requirements](#requirements)
6. [Setup and Running Locally](#setup-and-running-locally)
7. [Running with Docker](#running-with-docker)
8. [Deployment (Railway)](#deployment-railway)
9. [Creating the First Admin](#creating-the-first-admin)
10. [Usage Guide](#usage-guide)
11. [Security](#security)
12. [Limitations and Future Scope](#limitations-and-future-scope)
13. [Team](#team)

---

## Features

**User**
- Register and log in securely
- Submit transactions (amount, merchant, location)
- View transaction history
- View fraud alerts raised on their transactions
- Import transaction history from a CSV file
- View risk reports

**Admin**
- Configure detection thresholds (amount, velocity, time window, z-score)
- Update algorithm parameters (rule weights)
- Review fraud alerts as *Confirmed Fraud* or *False Positive*
- View the audit log of admin actions
- View registered users, their last login, login count, and recent login history with IP addresses

**System**
- Risk score with a written explanation for every flagged transaction
- Role-based access control (ADMIN and USER)
- Duplicate alert protection
- Animated radar-themed interface

---

## How Fraud Detection Works

When a transaction is submitted, four rules each produce a score from 0 to 100%:

| Rule | What it checks | Default |
|---|---|---|
| Amount | Compares the amount with the admin threshold | 50,000 |
| Velocity | Number of transactions by the user in a recent time window | 5 in 10 minutes |
| Location | Whether the location is new for this user | New location raises risk |
| Z-score | How unusual the amount is compared with the user's own history | Threshold 3.0 |

**Final risk score** = weighted sum of the four rule scores.

Default weights: Amount 30%, Velocity 25%, Location 20%, Z-score 25%.

- Risk score **50% or higher**: transaction is `FLAGGED` and a fraud alert is created, with a reason showing each rule's contribution.
- Risk score **below 50%**: transaction is `APPROVED`.

**Adaptive learning:** when an admin marks an alert as *Confirmed Fraud* or *False Positive*, the feedback is stored and the rule weights are adjusted. Weights stay between 0 and 1 and always sum to 1.0.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Web layer | Jakarta Servlet 6.0 (Servlets and Filters) |
| Server | Apache Tomcat 10.1 |
| Database | MySQL with JDBC (mysql-connector-j) |
| Build tool | Maven (packages a WAR file) |
| Password security | BCrypt (jBCrypt) |
| JSON | Jackson |
| Front end | HTML, CSS, JavaScript |
| Version control | Git and GitHub |
| Deployment | Docker and Railway |

**Architecture:**

```
Browser -> Filters (AuthFilter, AdminFilter) -> Servlets (controllers)
        -> FraudDetectionService (business logic) -> JDBC -> MySQL
```

---

## Project Structure

> Check these names against your actual folders and edit if any differ.

```
FraudDetectionSystem/
├── pom.xml                         # Maven configuration (packaging: war)
├── Dockerfile                      # Two-stage build: Maven, then Tomcat 10.1
├── docker-entrypoint.sh            # Container startup script
├── README.md
├── database/
│   └── schema.sql                  # Database tables (no real user data)
├── screenshots/                    # Images used in this README
└── src/
    └── main/
        ├── java/com/frauddetection/
        │   ├── servlet/            # LoginServlet, RegisterServlet, AdminServlet,
        │   │                       # UserManagementServlet, SessionInfoServlet, ...
        │   ├── filter/             # AuthFilter, AdminFilter
        │   ├── service/            # FraudDetectionService (risk scoring)
        │   └── util/               # DBConnection
        └── webapp/
            ├── WEB-INF/web.xml
            ├── login.html
            ├── dashboard.html
            ├── transaction.html
            ├── style.css
            ├── favicon.svg
            └── images/radar-logo.svg
```

**Main URLs**

| URL | Access | Purpose |
|---|---|---|
| `/login.html`, `/register` | Public | Sign in and sign up |
| `/dashboard.html` | Logged in | Main dashboard |
| `/transaction.html`, `/transaction-history` | Logged in | Create and view transactions |
| `/import-transactions` | Logged in | CSV import |
| `/alerts` | Logged in | Fraud alerts |
| `/reports` | Logged in | Risk reports |
| `/admin` | Admin only | Administration panel |
| `/algorithm-params` | Admin only | Rule weights |
| `/audit-log` | Admin only | Admin action history |
| `/admin-users` | Admin only | Users and login history |

---

## Requirements

- **Java JDK 17** (JDK 17 is what the Docker build uses)
- **Apache Maven 3.9+**
- **MySQL 8.x**
- **Apache Tomcat 10.1.x** (must be 10.1, because the code uses `jakarta.servlet.*`)
- **Git**
- *Optional:* Docker

---

## Setup and Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/AMAN9521-code/FraudDetectionSystem.git
cd FraudDetectionSystem
```

### 2. Create the database

Log in to MySQL as root and create the database and the application user the app expects by default:

```sql
CREATE DATABASE fraud_detection;
CREATE USER 'fraud_app'@'localhost' IDENTIFIED BY 'the_password_set_in_LOCAL_PASSWORD';
GRANT ALL PRIVILEGES ON fraud_detection.* TO 'fraud_app'@'localhost';
FLUSH PRIVILEGES;
```

Use the same password that is set as `LOCAL_PASSWORD` in `src/main/java/com/frauddetection/util/DBConnection.java`. Then load the schema:

```bash
mysql -u fraud_app -p fraud_detection < database/schema.sql
```

### 3. Configure the database connection

`DBConnection.java` chooses the database in this order:

1. **`MYSQL_URL`** environment variable (used on Railway). If it is set, the app connects with it.
2. **Individual variables** `MYSQLHOST`, `MYSQLPORT`, `MYSQLDATABASE`, `MYSQLUSER`, `MYSQLPASSWORD`. All five must be set and non-empty.
3. **Local default** (used when none of the above are set):

| Setting | Local default |
|---|---|
| Host and port | `localhost:3306` |
| Database | `fraud_detection` |
| User | `fraud_app` |
| Password | `LOCAL_PASSWORD` constant in `DBConnection.java` |

**For a normal local run you set nothing.** Create the `fraud_detection` database and `fraud_app` user as in Step 2, and the app connects automatically.

To use a different local database, set environment variables before starting Tomcat. On Windows PowerShell:

```powershell
$env:MYSQL_URL="mysql://your_user:your_password@localhost:3306/your_database"
```

Or, on Linux or macOS:

```bash
export MYSQL_URL="mysql://your_user:your_password@localhost:3306/your_database"
```

Tomcat must be started from the same terminal so it sees the variable.

> **Security note:** the local default password is stored in the source code for development convenience. It is for local use only. Do not reuse it for any real database.

### 4. Build the project

```bash
mvn clean package -DskipTests
```

This creates `target/fraud-detection.war`.

### 5. Deploy to Tomcat 10.1

1. Delete the default apps in Tomcat's `webapps/` folder (optional but tidy).
2. Copy the WAR into `webapps/` and rename it `ROOT.war`:

   ```bash
   cp target/fraud-detection.war /path/to/tomcat/webapps/ROOT.war
   ```

3. Start Tomcat:

   ```bash
   /path/to/tomcat/bin/catalina.sh run        # Linux / macOS
   C:\path\to\tomcat\bin\catalina.bat run     # Windows
   ```

4. Open **http://localhost:8080/** in your browser. You should see the login page.


---

## Running with Docker

The included Dockerfile builds the WAR with Maven and runs it on Tomcat 10.1.

```bash
docker build -t radar-fraud-detection .

docker run -p 8080:8080 \
  -e MYSQL_URL="mysql://fraud_app:your_password@host.docker.internal:3306/fraud_detection" \
  radar-fraud-detection
```

`host.docker.internal` lets the container reach MySQL running on your own computer. Without `MYSQL_URL`, the container would try `localhost`, which is the container itself and has no database.

Open **http://localhost:8080/**.

---

## Deployment (Railway)

The live demo runs on Railway:

1. Push the code to GitHub.
2. In Railway, create a project from the GitHub repository. Railway builds the `Dockerfile` automatically.
3. Add a **MySQL** service to the same project.
4. In the app service's **Variables** tab, add `MYSQL_URL` as a reference to the MySQL service's `MYSQL_URL` variable. The app reads this variable first. (The individual `MYSQLHOST`, `MYSQLPORT`, `MYSQLDATABASE`, `MYSQLUSER`, `MYSQLPASSWORD` variables also work as a fallback.)
5. Run `database/schema.sql` on the Railway MySQL database.
6. Generate a public domain under the service's **Settings -> Networking**.

Every `git push` to `main` triggers an automatic rebuild and redeploy.

---

## Creating the First Admin

Passwords are stored as BCrypt hashes, so you cannot insert a plain-text password directly. Use this method:

1. Open the app and **register** a new account (for example, name `Admin`).
2. Promote it to admin in MySQL:

   ```sql
   UPDATE users SET role = 'ADMIN' WHERE email = 'your-registered-email';
   ```

3. Log out and log in again with that email and password. You will see the Administration card on the dashboard.

Admin credentials are not stored in this repository. If you are a reviewer and need access, please use the credentials provided in the submission form.

---

## Usage Guide

**As a user**
1. Register, then log in.
2. Click **New Transaction** and submit an amount, merchant, and location.
3. A normal transaction is `APPROVED`. A large amount (above the threshold), many quick transactions, or an unusual location can raise the risk score above 50% and create an alert.
4. Open **Fraud Alerts** to see flagged transactions and the reason for each.
5. Open **Risk Reports** for fraud statistics.

**As an admin**
1. Log in with an admin account and open **Administration**.
2. Change detection thresholds or algorithm weights. Each change is written to the audit log.
3. Review alerts and mark them *Confirmed Fraud* or *False Positive*. This updates the rule weights.
4. Open **Users & Logins** to see registered users, last login time, login counts, and recent logins.

> **Testing tip:** a browser keeps one login session per site. To test admin and user side by side, use a normal window for one and an Incognito window for the other. To switch accounts in one window, log out first.

---

## Security

- Passwords hashed with **BCrypt** (no plain-text passwords)
- **Session-based login** with `AuthFilter` (login required) and `AdminFilter` (admin only)
- **Role-based access control:** normal users receive HTTP 403 on admin URLs
- **Prepared statements** for all database queries, which prevents SQL injection
- **Output escaping** on pages that display user-entered names and emails
- **Audit logging** of admin actions (configuration changes, algorithm changes, alert reviews, CSV imports)
- **Login history** with IP addresses (`X-Forwarded-For` is read so the real client IP is recorded behind Railway's proxy)
- Duplicate alert protection and input validation on transactions

---

## Database Tables

| Table | Purpose |
|---|---|
| `users` | Name, email, password hash, role (`ADMIN` or `USER`), last login |
| `transactions` | Amount, merchant, location, time, status, risk score |
| `fraud_alerts` | Reason, risk score, review status (`OPEN`, `CONFIRMED_FRAUD`, `FALSE_POSITIVE`) |
| `detection_config` | Amount threshold, velocity limit, time window, z-score threshold |
| `algorithm_params` | Rule weights and feedback scores |
| `audit_log` | Admin actions with user and timestamp |
| `login_history` | Every successful login with time and IP address |

---

## Limitations and Future Scope

**Current limitations**
- The model uses only three features (amount, merchant, location). It does not see transaction history, velocity or time of day, which the rule engine in the main application covers.
- The dataset is small (1,500 rows) and was prepared for this project. It is not real banking data.
- The reported scores come from one 80/20 split. The near-perfect result likely reflects an easily separable synthetic dataset and should not be read as real-world accuracy.
- The API has no authentication, so do not expose it publicly without protection.


**Future scope**
- Add features such as transaction time, user history, velocity and device or IP information
- Retrain automatically from admin-reviewed alerts (confirmed fraud and false positives) in the main application
- Add API authentication and request validation
- Compare other models (Gradient Boosting, XGBoost) and report cross-validated scores
- Integration with real payment systems

---

