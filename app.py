import os
import sqlite3
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from werkzeug.security import check_password_hash, generate_password_hash


APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "app.db")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me")

    login_manager = LoginManager()
    login_manager.login_view = "landing"
    login_manager.init_app(app)

    class User(UserMixin):
        def __init__(self, user_id: int, username: str):
            self.id = str(user_id)
            self.username = username

    @login_manager.user_loader
    def load_user(user_id: str):
        row = query_one("SELECT id, username FROM users WHERE id = ?", (user_id,))
        if not row:
            return None
        return User(row["id"], row["username"])

    @app.before_request
    def _ensure_db():
        init_db()
        if "mode" not in session:
            session["mode"] = "work"

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.get("/")
    def landing():
        if current_user.is_authenticated:
            return redirect(url_for("home"))
        return render_template("landing.html")

    @app.post("/signup")
    def signup():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("landing"))

        existing = query_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            flash("That username is already taken.", "danger")
            return redirect(url_for("landing"))

        pw_hash = generate_password_hash(password)
        execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, pw_hash, datetime.utcnow().isoformat(timespec="seconds")),
        )
        flash("User created. You can log in now.", "success")
        return redirect(url_for("landing"))

    @app.post("/login")
    def login():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        row = query_one(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        )
        if not row or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("landing"))

        user = User(row["id"], row["username"])
        login_user(user)
        flash("Welcome back!", "success")
        return redirect(url_for("home"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("landing"))

    @app.get("/home")
    @login_required
    def home():
        mode = session.get("mode", "work")
        return render_template("home.html", mode=mode)

    @app.post("/mode")
    @login_required
    def set_mode():
        mode = request.form.get("mode")
        if mode not in ("work", "personal"):
            flash("Invalid mode.", "danger")
            return redirect(url_for("home"))
        session["mode"] = mode
        return redirect(request.referrer or url_for("home"))

    @app.get("/people")
    @login_required
    def people():
        mode = session.get("mode", "work")
        rows = query_all(
            """
            SELECT id, name, identifier, is_direct_report
            FROM people
            WHERE owner_user_id = ? AND COALESCE(context, 'work') = ?
            ORDER BY id DESC
            """,
            (current_user.id, mode),
        )
        return render_template("people.html", people=rows, mode=mode)

    @app.post("/people/add")
    @login_required
    def add_person():
        mode = session.get("mode", "work")
        name = (request.form.get("name") or "").strip()
        identifier = (request.form.get("identifier") or "").strip()
        is_dr = 1 if (mode == "work" and request.form.get("is_direct_report") == "on") else 0

        if not name or not identifier:
            flash("First Name and Last Name are required.", "danger")
            return redirect(url_for("people"))

        execute(
            """
            INSERT INTO people (owner_user_id, name, identifier, is_direct_report, context, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                current_user.id,
                name,
                identifier,
                is_dr,
                mode,
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        flash("Person added.", "success")
        return redirect(url_for("people"))

    @app.get("/tasks")
    @login_required
    def tasks():
        mode = session.get("mode", "work")
        people_rows = query_all(
            "SELECT id, name, identifier FROM people WHERE owner_user_id = ? AND COALESCE(context, 'work') = ? ORDER BY name ASC",
            (current_user.id, mode),
        )
        task_rows = query_all(
            """
            SELECT
              t.id,
              t.description,
              t.assignee_type,
              t.assignee_person_id,
              p.name AS assignee_person_name,
              t.eta_date,
              t.status,
              t.created_at
            FROM tasks t
            LEFT JOIN people p ON p.id = t.assignee_person_id
            WHERE t.owner_user_id = ? AND COALESCE(t.context, 'work') = ?
            ORDER BY t.id DESC
            """,
            (current_user.id, mode),
        )
        return render_template(
            "tasks.html",
            people=people_rows,
            tasks=task_rows,
            statuses=["Open", "Assigned", "Closed", "On Hold"],
            mode=mode,
        )

    @app.post("/tasks/add")
    @login_required
    def add_task():
        mode = session.get("mode", "work")
        description = (request.form.get("description") or "").strip()
        assignee = request.form.get("assignee") or "self"
        eta_date = (request.form.get("eta_date") or "").strip()
        status = request.form.get("status") or "Open"

        if not description:
            flash("Task Description is required.", "danger")
            return redirect(url_for("tasks"))

        if status not in ("Open", "Assigned", "Closed", "On Hold"):
            flash("Invalid status.", "danger")
            return redirect(url_for("tasks"))

        assignee_type = "self"
        assignee_person_id = None
        if assignee != "self":
            assignee_type = "person"
            try:
                assignee_person_id = int(assignee)
            except ValueError:
                flash("Invalid assignee.", "danger")
                return redirect(url_for("tasks"))

            owned = query_one(
                "SELECT id FROM people WHERE id = ? AND owner_user_id = ? AND COALESCE(context, 'work') = ?",
                (assignee_person_id, current_user.id, mode),
            )
            if not owned:
                flash("That assignee is not in your people/family list.", "danger")
                return redirect(url_for("tasks"))

        if eta_date:
            try:
                datetime.strptime(eta_date, "%Y-%m-%d")
            except ValueError:
                flash("ETA must be a valid date.", "danger")
                return redirect(url_for("tasks"))

        execute(
            """
            INSERT INTO tasks (
              owner_user_id,
              description,
              assignee_type,
              assignee_person_id,
              eta_date,
              status,
              context,
              created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                current_user.id,
                description,
                assignee_type,
                assignee_person_id,
                eta_date or None,
                status,
                mode,
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        
        # Check if JIRA task should be created
        create_jira = request.form.get("create_jira") == "on"
        jira_created = False
        jira_key = None
        
        if create_jira and mode == "work":
            jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
            jira_email = os.environ.get("JIRA_EMAIL")
            jira_token = os.environ.get("JIRA_API_TOKEN")
            jira_project = os.environ.get("JIRA_PROJECT_KEY", "SCRUM")
            
            if all([jira_url, jira_email, jira_token]):
                try:
                    import requests
                    from requests.auth import HTTPBasicAuth
                    
                    api_url = f"{jira_url}/rest/api/3/issue"
                    auth = HTTPBasicAuth(jira_email, jira_token)
                    headers = {
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    }
                    
                    payload = {
                        "fields": {
                            "project": {"key": jira_project},
                            "summary": description,
                            "issuetype": {"name": "Task"}
                        }
                    }
                    
                    # Add due date if provided
                    if eta_date:
                        payload["fields"]["duedate"] = eta_date
                    
                    response = requests.post(api_url, json=payload, headers=headers, auth=auth, verify=False)
                    response.raise_for_status()
                    result = response.json()
                    jira_key = result.get("key")
                    jira_created = True
                except Exception as e:
                    flash(f"Task added locally, but JIRA creation failed: {e}", "warning")
        
        if jira_created and jira_key:
            flash(f"Task added to your task list and JIRA ({jira_key}).", "success")
        else:
            flash("Task added to your task list.", "success")
        return redirect(url_for("tasks"))

    @app.get("/jira-tasks")
    @login_required
    def jira_tasks():
        mode = session.get("mode", "work")
        if mode != "work":
            flash("JIRA Tasks is available in Work mode only.", "info")
            return redirect(url_for("home"))

        jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
        jira_email = os.environ.get("JIRA_EMAIL")
        jira_token = os.environ.get("JIRA_API_TOKEN")

        jira_configured = bool(jira_url and jira_email and jira_token)
        issues = []
        error_message = None

        if jira_configured:
            try:
                import requests
                from requests.auth import HTTPBasicAuth
                
                # Use JIRA REST API v3 search/jql endpoint
                api_url = f"{jira_url}/rest/api/3/search/jql"
                auth = HTTPBasicAuth(jira_email, jira_token)
                headers = {"Accept": "application/json"}
                params = {
                    "jql": "assignee = currentUser() ORDER BY updated DESC",
                    "maxResults": 50,
                    "fields": "summary,status,duedate,assignee"
                }
                
                response = requests.get(api_url, headers=headers, params=params, auth=auth, verify=False)
                response.raise_for_status()
                data = response.json()
                
                for i in data.get("issues", []):
                    fields = i.get("fields", {})
                    status_obj = fields.get("status") or {}
                    assignee_obj = fields.get("assignee") or {}
                    duedate = fields.get("duedate") or ""
                    
                    issues.append({
                        "key": i.get("key", ""),
                        "summary": fields.get("summary", ""),
                        "status": status_obj.get("name", "Unknown"),
                        "duedate": str(duedate)[:10] if duedate else "",
                        "assignee": assignee_obj.get("displayName", ""),
                        "url": f"{jira_url}/browse/{i.get('key', '')}",
                    })
            except Exception as e:
                error_message = str(e)

        return render_template(
            "jira_tasks.html",
            jira_configured=jira_configured,
            issues=issues,
            error_message=error_message,
            mode=mode,
        )

    @app.get("/jira-mcp")
    @login_required
    def jira_mcp():
        mode = session.get("mode", "work")
        if mode != "work":
            flash("JIRA MCP is available in Work mode only.", "info")
            return redirect(url_for("home"))
        return render_template("jira_mcp.html", mode=mode)

    @app.get("/jira-mcp/view")
    @login_required
    def jira_mcp_view():
        mode = session.get("mode", "work")
        if mode != "work":
            flash("JIRA MCP is available in Work mode only.", "info")
            return redirect(url_for("home"))
        
        jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
        jira_email = os.environ.get("JIRA_EMAIL")
        jira_token = os.environ.get("JIRA_API_TOKEN")
        
        issues = []
        error_message = None
        
        if all([jira_url, jira_email, jira_token]):
            try:
                import requests
                from requests.auth import HTTPBasicAuth
                
                api_url = f"{jira_url}/rest/api/3/search/jql"
                auth = HTTPBasicAuth(jira_email, jira_token)
                headers = {"Accept": "application/json"}
                params = {
                    "jql": "assignee = currentUser() ORDER BY updated DESC",
                    "maxResults": 50,
                    "fields": "summary,status,duedate,assignee,priority,created"
                }
                
                response = requests.get(api_url, headers=headers, params=params, auth=auth, verify=False)
                response.raise_for_status()
                data = response.json()
                
                for i in data.get("issues", []):
                    fields = i.get("fields", {})
                    status_obj = fields.get("status") or {}
                    assignee_obj = fields.get("assignee") or {}
                    priority_obj = fields.get("priority") or {}
                    duedate = fields.get("duedate") or ""
                    
                    issues.append({
                        "key": i.get("key", ""),
                        "summary": fields.get("summary", ""),
                        "status": status_obj.get("name", "Unknown"),
                        "priority": priority_obj.get("name", ""),
                        "duedate": str(duedate)[:10] if duedate else "",
                        "assignee": assignee_obj.get("displayName", ""),
                        "url": f"{jira_url}/browse/{i.get('key', '')}",
                    })
            except Exception as e:
                error_message = str(e)
        else:
            error_message = "JIRA not configured"
        
        return render_template("jira_mcp_view.html", issues=issues, error_message=error_message, mode=mode)

    @app.get("/jira-mcp/create")
    @login_required
    def jira_mcp_create():
        mode = session.get("mode", "work")
        if mode != "work":
            flash("JIRA MCP is available in Work mode only.", "info")
            return redirect(url_for("home"))
        return render_template("jira_mcp_create.html", mode=mode)

    @app.get("/describe-process")
    @login_required
    def describe_process():
        mode = session.get("mode", "work")
        if mode != "work":
            flash("Describe Process is available in Work mode only.", "info")
            return redirect(url_for("home"))
        
        jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
        jira_email = os.environ.get("JIRA_EMAIL")
        jira_token = os.environ.get("JIRA_API_TOKEN")
        
        issues = []
        error_message = None
        
        if all([jira_url, jira_email, jira_token]):
            try:
                import requests
                from requests.auth import HTTPBasicAuth
                
                api_url = f"{jira_url}/rest/api/3/search/jql"
                auth = HTTPBasicAuth(jira_email, jira_token)
                headers = {"Accept": "application/json"}
                params = {
                    "jql": "assignee = currentUser() ORDER BY updated DESC",
                    "maxResults": 50,
                    "fields": "summary,status,description"
                }
                
                response = requests.get(api_url, headers=headers, params=params, auth=auth, verify=False)
                response.raise_for_status()
                data = response.json()
                
                for i in data.get("issues", []):
                    fields = i.get("fields", {})
                    status_obj = fields.get("status") or {}
                    
                    issues.append({
                        "key": i.get("key", ""),
                        "summary": fields.get("summary", ""),
                        "status": status_obj.get("name", "Unknown"),
                        "url": f"{jira_url}/browse/{i.get('key', '')}",
                    })
            except Exception as e:
                error_message = str(e)
        else:
            error_message = "JIRA not configured"
        
        return render_template("describe_process.html", issues=issues, error_message=error_message, mode=mode)

    @app.get("/describe-process/<issue_key>")
    @login_required
    def view_process_flow(issue_key):
        mode = session.get("mode", "work")
        if mode != "work":
            return redirect(url_for("home"))
        
        jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
        jira_email = os.environ.get("JIRA_EMAIL")
        jira_token = os.environ.get("JIRA_API_TOKEN")
        gemini_key = os.environ.get("GEMINI_API_KEY")
        
        issue_data = None
        process_steps = None
        error_message = None
        gemini_error = None
        
        if not all([jira_url, jira_email, jira_token]):
            error_message = "JIRA not configured"
        else:
            try:
                import requests
                from requests.auth import HTTPBasicAuth
                
                # Fetch JIRA issue details
                api_url = f"{jira_url}/rest/api/3/issue/{issue_key}"
                auth = HTTPBasicAuth(jira_email, jira_token)
                headers = {"Accept": "application/json"}
                
                response = requests.get(api_url, headers=headers, auth=auth, verify=False)
                response.raise_for_status()
                issue = response.json()
                
                fields = issue.get("fields", {})
                status_obj = fields.get("status") or {}
                
                # Extract description text from Atlassian Document Format
                description_raw = fields.get("description")
                description_text = ""
                if description_raw and isinstance(description_raw, dict):
                    # Parse ADF format
                    def extract_text(node):
                        text = ""
                        if isinstance(node, dict):
                            if node.get("type") == "text":
                                text += node.get("text", "")
                            for child in node.get("content", []):
                                text += extract_text(child)
                        elif isinstance(node, list):
                            for item in node:
                                text += extract_text(item)
                        return text
                    description_text = extract_text(description_raw)
                elif isinstance(description_raw, str):
                    description_text = description_raw
                
                issue_data = {
                    "key": issue.get("key", ""),
                    "summary": fields.get("summary", ""),
                    "status": status_obj.get("name", "Unknown"),
                    "description": description_text,
                    "url": f"{jira_url}/browse/{issue.get('key', '')}",
                }
                
                # Generate Mermaid diagram using Groq (fallback to Gemini)
                groq_key = os.environ.get("GROQ_API_KEY")
                llm_error = None
                mermaid_diagram = None
                
                if groq_key and description_text.strip():
                    try:
                        from groq import Groq
                        
                        client = Groq(api_key=groq_key)
                        
                        prompt = f"""Analyze this JIRA task and create a process flow diagram using Mermaid syntax.

JIRA Task: {issue_data['summary']}

Description:
{description_text}

Generate a Mermaid flowchart that shows the sequence of steps or process flow for completing this task.
Use the flowchart TD (top-down) format.
Make it clear and easy to understand.
Only output the Mermaid code, nothing else. Do not include ```mermaid or ``` markers."""
                        
                        response = client.chat.completions.create(
                            model="llama-3.1-8b-instant",
                            messages=[{"role": "user", "content": prompt}],
                            temperature=0.3,
                            max_tokens=1024
                        )
                        mermaid_diagram = response.choices[0].message.content.strip()
                        
                        # Clean up any markdown code blocks
                        if mermaid_diagram.startswith("```"):
                            lines = mermaid_diagram.split("\n")
                            mermaid_diagram = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                        
                    except Exception as e:
                        mermaid_diagram = None
                        llm_error = str(e)
                elif gemini_key and description_text.strip():
                    # Fallback to Gemini if Groq not configured
                    try:
                        import google.generativeai as genai
                        
                        genai.configure(api_key=gemini_key)
                        model = genai.GenerativeModel('gemini-2.0-flash')
                        
                        prompt = f"""Analyze this JIRA task and create a process flow diagram using Mermaid syntax.

JIRA Task: {issue_data['summary']}

Description:
{description_text}

Generate a Mermaid flowchart that shows the sequence of steps or process flow for completing this task.
Use the flowchart TD (top-down) format.
Make it clear and easy to understand.
Only output the Mermaid code, nothing else. Do not include ```mermaid or ``` markers."""
                        
                        response = model.generate_content(prompt)
                        mermaid_diagram = response.text.strip()
                        
                        # Clean up any markdown code blocks
                        if mermaid_diagram.startswith("```"):
                            lines = mermaid_diagram.split("\n")
                            mermaid_diagram = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
                        
                    except Exception as e:
                        mermaid_diagram = None
                        llm_error = str(e)
                elif not groq_key and not gemini_key:
                    pass  # No API key configured
                
                process_steps = mermaid_diagram  # Pass to template
                gemini_error = llm_error
                    
            except Exception as e:
                error_message = str(e)
        
        groq_key = os.environ.get("GROQ_API_KEY")
        return render_template(
            "process_flow.html",
            issue=issue_data,
            process_steps=process_steps,
            gemini_configured=bool(groq_key or gemini_key),
            gemini_error=gemini_error,
            error_message=error_message,
            mode=mode
        )

    @app.post("/jira-mcp/create")
    @login_required
    def jira_mcp_create_submit():
        mode = session.get("mode", "work")
        if mode != "work":
            return redirect(url_for("home"))
        
        summary = (request.form.get("summary") or "").strip()
        description = (request.form.get("description") or "").strip()
        issue_type = request.form.get("issue_type") or "Task"
        priority = request.form.get("priority") or ""
        due_date = (request.form.get("due_date") or "").strip()
        
        if not summary:
            flash("Summary is required.", "danger")
            return redirect(url_for("jira_mcp_create"))
        
        jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
        jira_email = os.environ.get("JIRA_EMAIL")
        jira_token = os.environ.get("JIRA_API_TOKEN")
        jira_project = os.environ.get("JIRA_PROJECT_KEY", "SCRUM")
        
        if not all([jira_url, jira_email, jira_token]):
            flash("JIRA not configured.", "danger")
            return redirect(url_for("jira_mcp_create"))
        
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            api_url = f"{jira_url}/rest/api/3/issue"
            auth = HTTPBasicAuth(jira_email, jira_token)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            payload = {
                "fields": {
                    "project": {"key": jira_project},
                    "summary": summary,
                    "issuetype": {"name": issue_type}
                }
            }
            
            if description:
                payload["fields"]["description"] = {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}]
                        }
                    ]
                }
            
            if priority:
                payload["fields"]["priority"] = {"name": priority}
            
            if due_date:
                payload["fields"]["duedate"] = due_date
            
            response = requests.post(api_url, json=payload, headers=headers, auth=auth, verify=False)
            response.raise_for_status()
            result = response.json()
            
            jira_key = result.get("key")
            flash(f"JIRA task created: {jira_key}", "success")
            return redirect(url_for("jira_mcp_view"))
        
        except Exception as e:
            flash(f"Failed to create JIRA task: {e}", "danger")
            return redirect(url_for("jira_mcp_create"))

    @app.get("/contact")
    @login_required
    def contact():
        mode = session.get("mode", "work")
        return render_template("contact.html", mode=mode)

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS people (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner_user_id INTEGER NOT NULL,
          name TEXT NOT NULL,
          identifier TEXT NOT NULL,
          is_direct_report INTEGER NOT NULL DEFAULT 0,
          context TEXT NOT NULL DEFAULT 'work' CHECK (context IN ('work', 'personal')),
          created_at TEXT NOT NULL,
          FOREIGN KEY (owner_user_id) REFERENCES users(id)
        )
        """
    )
    try:
        db.execute("ALTER TABLE people ADD COLUMN context TEXT NOT NULL DEFAULT 'work'")
        db.commit()
    except sqlite3.OperationalError:
        pass
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner_user_id INTEGER NOT NULL,
          description TEXT NOT NULL,
          assignee_type TEXT NOT NULL CHECK (assignee_type IN ('self', 'person')),
          assignee_person_id INTEGER NULL,
          eta_date TEXT NULL,
          status TEXT NOT NULL CHECK (status IN ('Open', 'Assigned', 'Closed', 'On Hold')),
          context TEXT NOT NULL DEFAULT 'work' CHECK (context IN ('work', 'personal')),
          created_at TEXT NOT NULL,
          FOREIGN KEY (owner_user_id) REFERENCES users(id),
          FOREIGN KEY (assignee_person_id) REFERENCES people(id)
        )
        """
    )
    try:
        db.execute("ALTER TABLE tasks ADD COLUMN context TEXT NOT NULL DEFAULT 'work'")
    except sqlite3.OperationalError:
        pass
    db.commit()


def query_one(sql: str, params: tuple):
    cur = get_db().execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row


def query_all(sql: str, params: tuple):
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return rows


def execute(sql: str, params: tuple):
    db = get_db()
    db.execute(sql, params)
    db.commit()


# Create app instance for gunicorn
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)


