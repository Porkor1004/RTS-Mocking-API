Restaurant Reservation System (RTS) - Mock API
This repository provides a Mock API for a Restaurant Reservation System, built with Node.js and Express. It is designed to simulate a real production environment for API integration and security testing.

🛠 Tech Stack & Installation
Core: Node.js, Express, JWT (JsonWebToken)

Installation: 1. npm install
2. npm start

Default Port: http://localhost:3001

🗺 API Features
Authentication: Full /auth/register and /auth/login flow with JWT issuance.

Reservations: Manage table bookings via GET /reservations/my and POST /reservations.

Admin Access: Role-based access control (RBAC) for restaurant profile management.

📂 Project Structure
server.js: Main application logic and in-memory database.

package.json: Dependency and script management.

.gitignore: Configured to exclude node_modules and sensitive files.

Educational Note: This server is intended for testing purposes. All data is stored in-memory and will reset upon server restart.