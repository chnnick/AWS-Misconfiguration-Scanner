# AWS-Misconfiguration-Scanner
CY4930 Capstone Project

FastAPI Backend

To start follow these steps:
1. Activate the venv (if you use it):
`cd /Users/silverfox/SCHOOL/AWS-Misconfiguration-Scanner/backend`
ENSURE YOU HAVE A VIRTUAL ENVIRONMENT (Example .venv)
`source .venv/bin/activate`

2. Install deps (if needed):
`pip install -r requirements.txt`

3. Activate docker
  * a. open docker desktop (to ensure it is running)
  * b. `docker ps` (list all containers)
  * c. `docker compose up` (spin up the container)
  * d. wait like 20 sec  (wait for it to fully spin up)
TO MANUALLY LOAD SCHEMA: (-p field references the password within your env file)
    * `docker exec -it cspm-neo4j cypher-shell -u neo4j -p password123 --file /var/lib/neo4j/import/schema.cypher`
  * e. `docker ps`  (list ur docker containers again, to show it works)
  * f. `docker compose down -v`  (delete containers once no longer required)

4. Run the API:
`uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`

React + Vite Frontend

## ⚖️ Acknowledgments & Third-Party Notices

This project uses [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs for deploying intentionally vulnerable AWS environments. CloudGoat is licensed under the [BSD 3-Clause License](https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/LICENSE).

We do not claim ownership of CloudGoat scenarios. All CloudGoat-related code and configurations remain under their original license and copyright by Rhino Security Labs.

---

