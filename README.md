# RADAR – AI-Powered Fraud Detection System

**R**isk **A**nalysis and **D**etection of **A**nonymous **R**esponse
*Detect / Analyze / Prevent*

A Java web application that monitors financial transactions, scores each one for fraud risk, raises alerts for suspicious activity, and lets administrators tune and improve detection from a dashboard.

- **Live demo:** https://frauddetectionsystem-production-3ecc.up.railway.app/
  *(hosted on Railway's trial plan; if the link is down, run the project locally using the steps below)*

---

## 1. Features

### User
- Register and log in securely
- Create transactions (amount, merchant, location)
- View transaction history
- View fraud alerts raised on their transactions
- Import transaction history from a CSV file
- View risk reports

### Admin
- Configure detection thresholds (amount, velocity, time window, z-score)
- Review fraud alerts as **Confirmed Fraud** or **False Positive**
- Adjust algorithm rule weights (feedback-driven)
- View the audit log of administrative actions
- View all registered users, last login time, login count and recent login history

### Security
- Passwords hashed with **BCrypt**
- Session-based login with **role-based access control** (`AuthFilter`, `AdminFilter`)
- Admin pages blocked for normal users (HTTP 403)
- SQL injection protection through `PreparedStatement`
- Audit logging of important admin actions

---

## 2. How Fraud Detection Works

Each transaction is checked by four rules, each producing a score from 0 to 100%:

|   Rule   |                  What it checks                          | Default         |
|----------|----------------------------------------------------------|-----------------|
| Amount   | Amount compared with the admin-set threshold             | ₹50,000         |
| Velocity | Number of transactions by the user in a recent window    | 5 in 10 minutes |
| Location | Whether the location is new for this user                | –               |
| Z-score  | How unusual the amount is against the user's own history | 3.0             |

The final **risk score** is a weighted sum of the four rule scores (default weights: Amount 30%, Velocity 25%, Location 20%, Z-score 25%).

- Risk **≥ 50%** → transaction is **FLAGGED** and a fraud alert is created, with a reason explaining each rule's contribution.
- Risk **< 50%** → transaction is **APPROVED**.

When an admin marks an alert as *Confirmed Fraud* or *False Positive*, that feedback adjusts the rule weights, so rules that catch real fraud gain influence and rules that cause false alarms lose it.

---

## 3. Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Web layer | Jakarta Servlet 6.0 |
| Server | Apache Tomcat 10.1 |
| Database | MySQL with JDBC (mysql-connector-j) |
| Build tool | Maven (packages a `.war` file) |
| Security | jBCrypt |
| Front end | HTML, CSS, JavaScript |
| Deployment | Docker, Railway |
| Tools | VS Code, Git, GitHub |

---

## 4. Requirements

To run locally you need:

- **JDK 17** or newer
- **Apache Maven 3.9+**
- **MySQL 8+**
- **Apache Tomcat 10.1** (must be 10.x: it uses `jakarta.servlet`, not `javax.servlet`)
- Git

---

## 5. Project Structure

```
FraudDetectionSystem/
├── pom.xml                         # Maven build file (WAR packaging)
├── Dockerfile                      # Two-stage build: Maven -> Tomcat 10.1
├── docker-entrypoint.sh            # Container start script
├── database/
│   └── schema.sql                  # Database tables and setup
├── screenshots/                    # Screenshots used in this README
└── src/main/
    ├── java/com/frauddetection/
    │   ├── servlet/                # Login, Register, Transaction, Alerts,
    │   │                           # Reports, Admin, Audit Log, User Management...
    │   ├── filter/                 # AuthFilter, AdminFilter
    │   ├── service/                # FraudDetectionService (risk scoring)
    │   └── util/                   # DBConnection
    └── webapp/
        ├── login.html, register.html, dashboard.html, transaction.html
        ├── style.css               # RADAR theme and animations
        ├── favicon.svg
        ├── images/
        └── WEB-INF/web.xml
```

---

## 6. Setup and Run Locally

### Step 1: Clone the repository
```bash
git clone https://github.com/AMAN9521-code/FraudDetectionSystem.git
cd FraudDetectionSystem
```

### Step 2: Create the database
```bash
mysql -u root -p
```
```sql
CREATE DATABASE frauddb;
USE frauddb;
SOURCE database/schema.sql;
```

### Step 3: Configure the database connection
Set the connection details (host, port, database name, username, password) used by `DBConnection.java`. On Railway these come from environment variables; locally, point them at your MySQL server.

### Step 4: Build the project
```bash
mvn clean package -DskipTests
```
This creates `target/fraud-detection.war`.

### Step 5: Deploy to Tomcat
1. Copy `target/fraud-detection.war` into Tomcat's `webapps` folder (rename it `ROOT.war` to serve at `/`).
2. Start Tomcat (`bin/startup.bat` on Windows, `bin/startup.sh` on Linux/Mac).
3. Open **http://localhost:8080/**

### Run with Docker (alternative)
```bash
docker build -t radar-fraud-detection .
docker run -p 8080:8080 radar-fraud-detection
```
Pass the database settings to the container as environment variables.

---

## 7. Creating the First Admin

Passwords are stored as BCrypt hashes, so create the admin through the app:

1. Open the site and **register** a new account.
2. In MySQL, promote it to admin:
   ```sql
   UPDATE users SET role = 'ADMIN' WHERE email = 'your-email@example.com';
   ```
3. Log out and log in again. The Administration card now appears on the dashboard.

---

## 8. Database Tables

| Table | Purpose |
|---|---|
| `users` | Accounts: name, email, password hash, role, last login |
| `transactions` | Amount, merchant, location, time, status, risk score |
| `fraud_alerts` | Alert reason, risk score, review status |
| `detection_config` | Admin-configurable thresholds |
| `algorithm_params` | Rule weights and feedback scores |
| `audit_log` | Record of admin actions |
| `login_history` | Login time and IP address for each login |

---

## 9. Screenshots


            | Login |                            | User Dashboard |
|--------------------------------------|-----------------------------------------|
| ![Login](https://shorturl.at/01Kig)  | ![Dashboard](https://shorturl.at/LBwkv) |


---

## 10. Future Scope

- Trained machine-learning model (for example Weka or a Python model through an API)
- Email/SMS alerts for flagged transactions
- Device and IP based checks
- Charts on the reports page
- Logging of failed login attempts



