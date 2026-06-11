# NetGuard AI - Deployment Guide

NetGuard AI is designed to be deployed using Docker Compose for production environments and can be run locally for development.

## Production Deployment (Docker Compose)

The provided `docker-compose.yml` spins up the complete microservice architecture:
- **nginx**: Reverse proxy serving the compiled React frontend and routing `/api` and `/socket.io` to the backend.
- **backend**: Flask/Gunicorn eventlet server running the engines and API.
- **mysql**: Production database.
- **redis**: In-memory cache for Socket.IO message brokering and health score caching.

### Steps:
1. Clone the repository.
2. Navigate to the `docker/` directory.
3. Copy `.env.example` to `.env` and fill in your secure credentials (e.g., `MYSQL_ROOT_PASSWORD`, `OPENAI_API_KEY`).
4. Run the compose stack:
   ```bash
   docker-compose up -d --build
   ```
5. Apply database migrations inside the backend container:
   ```bash
   docker-compose exec backend flask db upgrade
   ```
6. Access the dashboard via `http://localhost:8080`.

## Local Development (Without Docker)

For rapid iteration, you can run the services directly on your host machine.

### Backend Setup
1. `cd backend`
2. Create virtualenv: `python -m venv venv` and activate it.
3. Install dependencies: `pip install -r requirements.txt`
4. Set environment variables (e.g., `FLASK_APP=run.py`, `FLASK_ENV=development`). The app falls back to an SQLite database (`app.db`) if MySQL is not available.
5. Initialize DB:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```
6. Run the server: `python run.py` (Runs on `http://localhost:5000`)

### Frontend Setup
1. `cd frontend`
2. Install Node dependencies: `npm install`
3. Start Vite dev server: `npm run dev`
4. Access the frontend at `http://localhost:5173`. API calls will be proxied to `localhost:5000` automatically.
