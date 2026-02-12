## Task Manager (MVP)

### What this app includes
- **Landing page** with **Login** and **Create new user**
- **User authentication** stored in a **SQLite** table (passwords hashed)
- After login: a top **Work / Personal** mode switch
- In **Work mode**:
  - **Manage my people**: add people + mark **Direct Report (DR)** yes/no (stored in a table)
  - **My task list**: create tasks with:
    - Task Description (text)
    - Assignee (dropdown: **Self** + your people)
    - ETA (date picker)
    - Status (Open / Assigned / Closed / On Hold)
    - **Add to My Task List** button (stored in a table)

### Tech
- Python **Flask** + server-rendered HTML (Jinja)
- **SQLite** database file: `app.db`

### Run locally (Windows PowerShell)
From the project folder:

```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`

### Notes
- This is an MVP intended for local/demo use. Next iterations can add role-based access, validations, search/filter, edit/delete, and nicer UI polish.


