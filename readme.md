 Data Cleaning and Processing Tool

1. Project Overview

This project is a web-based Data Cleaning and Processing Tool designed to allow users to upload datasets, apply structured cleaning rules, and generate processed outputs in a controlled environment.
The primary objective of the system is to streamline dataset preprocessing through a modular rule-based pipeline while ensuring secure access, controlled user management, and activity auditability.
To support secure multi-user usage, the system incorporates authentication, role-based access control (RBAC), logging, and structured account management.
________________________________________

2. Core Functionalities

 Data Cleaning Engine (Primary Component)
●	Dataset upload support
●	Column selection and rule application
●	Rule-based data transformations
●	Structured cleaning pipeline execution
●	Cleaned dataset output generation
●	Controlled execution of cleaning operations

The cleaning logic is modular and extendable, allowing additional transformation rules to be integrated without restructuring the system.
The architecture separates rule handling from user management to maintain clarity and maintainability.
________________________________________

3. Security and Access Control (Supporting Layer)

To ensure secure system usage, the application implements Role-Based Access Control (RBAC).

 Authentication
●	Secure password hashing using bcrypt
●	Login and logout functionality
●	Session-based authentication
●	Protected routes
●	Password validation rules
________________________________________

 4. Role-Based Access Control

●	Roles defined in ROLE_PERMISSIONS
●	Backend enforcement of permissions
●	Route-level role validation
●	No privilege escalation via frontend manipulation
________________________________________

 5. Secure User Registration Flow

Two separate flows exist:

Public Registration (/register)
●	Role automatically set to "user"
●	No role selection dropdown
●	Prevents privilege escalation

Admin User Creation (/admin/create-user)
●	Accessible only to admin users
●	Allows controlled role assignment
●	Logs administrative actions

This separation ensures strict backend control over privilege assignment.
________________________________________

6. Logging and Audit Trail

The system logs significant events, including:
●	Successful login
●	Failed login attempts
●	Self-registration
●	Admin-created accounts
●	Administrative actions
●	Data cleaning executions (if applicable)

Logging is implemented independently from core cleaning operations to ensure that logging failures do not disrupt primary system functionality.
________________________________________

7. Account Management

●	Soft delete (account disabling instead of permanent deletion)
●	Preserves historical audit records
●	Maintains integrity of activity logs
________________________________________

8. Database Structure

Current implementation includes:
●	users table
●	logs table

The schema is provided in schema.sql.

The database design prioritizes:
●	Clear role enforcement
●	Secure user management
●	Structured activity tracking
________________________________________

9. Seed Admin Account

For initial system setup, a seed admin account is provided.

 Username: admin
 Password: Admin@123

This enables administrative access without exposing role elevation publicly.
________________________________________

10. How to Run

(1)	Create a MySQL database.
(2)	Import schema.sql 
(3) Install dependencies:   pip install -r requirements.txt
(4) Run:   python app.py
(5) Access:   http://127.0.0.1:5000
________________________________________

11. Design Decisions

●	Cleaning logic is modular and extendable.
●	Role assignment is enforced strictly server-side.
●	Public registration is restricted to the standard user role.
●	Admin role assignment is isolated to protected routes.
●	Logging failures do not block core cleaning functionality.
●	Soft delete preserves audit history.
________________________________________

12. Future Enhancements

●	Expanded cleaning rule library
●	Advanced dataset validation mechanisms
●	Data preview improvements
●	Result versioning and history tracking
●	Pagination and filtering for logs
●	Enhanced processing analytics


