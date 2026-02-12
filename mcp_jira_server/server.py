"""
JIRA MCP Server
Provides tools for interacting with JIRA via Model Context Protocol
"""

import os
import json
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
import requests
from requests.auth import HTTPBasicAuth

# Load environment variables from parent directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# JIRA Configuration
JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")
JIRA_EMAIL = os.environ.get("JIRA_EMAIL")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SCRUM")

# Create MCP server
mcp = FastMCP("JIRA Server")


def get_jira_auth():
    """Get JIRA authentication"""
    return HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)


def get_headers():
    """Get common headers for JIRA API"""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }


@mcp.tool()
def list_jira_tasks(jql: str = None, max_results: int = 20) -> str:
    """
    List JIRA tasks/issues.
    
    Args:
        jql: JQL query string (default: assigned to current user)
        max_results: Maximum number of results to return (default: 20)
    
    Returns:
        JSON string with list of JIRA issues
    """
    if not all([JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        return json.dumps({"error": "JIRA not configured. Set JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN environment variables."})
    
    if jql is None:
        jql = "assignee = currentUser() ORDER BY updated DESC"
    
    try:
        api_url = f"{JIRA_URL}/rest/api/3/search/jql"
        params = {
            "jql": jql,
            "maxResults": max_results,
            "fields": "summary,status,duedate,assignee,priority,created"
        }
        
        response = requests.get(
            api_url, 
            headers=get_headers(), 
            params=params, 
            auth=get_jira_auth(), 
            verify=False
        )
        response.raise_for_status()
        data = response.json()
        
        issues = []
        for issue in data.get("issues", []):
            fields = issue.get("fields", {})
            status_obj = fields.get("status") or {}
            assignee_obj = fields.get("assignee") or {}
            priority_obj = fields.get("priority") or {}
            
            issues.append({
                "key": issue.get("key"),
                "summary": fields.get("summary"),
                "status": status_obj.get("name"),
                "assignee": assignee_obj.get("displayName"),
                "priority": priority_obj.get("name"),
                "duedate": fields.get("duedate"),
                "created": fields.get("created"),
                "url": f"{JIRA_URL}/browse/{issue.get('key')}"
            })
        
        return json.dumps({"total": data.get("total", 0), "issues": issues}, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_jira_task(issue_key: str) -> str:
    """
    Get details of a specific JIRA issue.
    
    Args:
        issue_key: The JIRA issue key (e.g., "SCRUM-1")
    
    Returns:
        JSON string with issue details
    """
    if not all([JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        return json.dumps({"error": "JIRA not configured."})
    
    try:
        api_url = f"{JIRA_URL}/rest/api/3/issue/{issue_key}"
        
        response = requests.get(
            api_url,
            headers=get_headers(),
            auth=get_jira_auth(),
            verify=False
        )
        response.raise_for_status()
        issue = response.json()
        
        fields = issue.get("fields", {})
        status_obj = fields.get("status") or {}
        assignee_obj = fields.get("assignee") or {}
        reporter_obj = fields.get("reporter") or {}
        priority_obj = fields.get("priority") or {}
        issuetype_obj = fields.get("issuetype") or {}
        
        result = {
            "key": issue.get("key"),
            "summary": fields.get("summary"),
            "description": fields.get("description"),
            "status": status_obj.get("name"),
            "assignee": assignee_obj.get("displayName"),
            "reporter": reporter_obj.get("displayName"),
            "priority": priority_obj.get("name"),
            "issuetype": issuetype_obj.get("name"),
            "duedate": fields.get("duedate"),
            "created": fields.get("created"),
            "updated": fields.get("updated"),
            "url": f"{JIRA_URL}/browse/{issue.get('key')}"
        }
        
        return json.dumps(result, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def create_jira_task(summary: str, description: str = None, issue_type: str = "Task", priority: str = None, due_date: str = None) -> str:
    """
    Create a new JIRA issue.
    
    Args:
        summary: The issue summary/title (required)
        description: The issue description (optional)
        issue_type: Type of issue - Task, Bug, Story, etc. (default: Task)
        priority: Priority - Highest, High, Medium, Low, Lowest (optional)
        due_date: Due date in YYYY-MM-DD format (optional)
    
    Returns:
        JSON string with created issue details
    """
    if not all([JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        return json.dumps({"error": "JIRA not configured."})
    
    try:
        api_url = f"{JIRA_URL}/rest/api/3/issue"
        
        payload = {
            "fields": {
                "project": {"key": JIRA_PROJECT_KEY},
                "summary": summary,
                "issuetype": {"name": issue_type}
            }
        }
        
        # Add optional fields
        if description:
            payload["fields"]["description"] = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": description}
                        ]
                    }
                ]
            }
        
        if priority:
            payload["fields"]["priority"] = {"name": priority}
        
        if due_date:
            payload["fields"]["duedate"] = due_date
        
        response = requests.post(
            api_url,
            json=payload,
            headers=get_headers(),
            auth=get_jira_auth(),
            verify=False
        )
        response.raise_for_status()
        result = response.json()
        
        return json.dumps({
            "success": True,
            "key": result.get("key"),
            "id": result.get("id"),
            "url": f"{JIRA_URL}/browse/{result.get('key')}",
            "message": f"Created JIRA issue {result.get('key')}"
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def update_jira_task(issue_key: str, summary: str = None, status: str = None, priority: str = None, due_date: str = None) -> str:
    """
    Update an existing JIRA issue.
    
    Args:
        issue_key: The JIRA issue key (e.g., "SCRUM-1") (required)
        summary: New summary/title (optional)
        status: New status - use transition name like "Done", "In Progress" (optional)
        priority: New priority (optional)
        due_date: New due date in YYYY-MM-DD format (optional)
    
    Returns:
        JSON string with update result
    """
    if not all([JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        return json.dumps({"error": "JIRA not configured."})
    
    try:
        updates_made = []
        
        # Update fields (summary, priority, duedate)
        if summary or priority or due_date:
            api_url = f"{JIRA_URL}/rest/api/3/issue/{issue_key}"
            payload = {"fields": {}}
            
            if summary:
                payload["fields"]["summary"] = summary
                updates_made.append("summary")
            if priority:
                payload["fields"]["priority"] = {"name": priority}
                updates_made.append("priority")
            if due_date:
                payload["fields"]["duedate"] = due_date
                updates_made.append("due_date")
            
            response = requests.put(
                api_url,
                json=payload,
                headers=get_headers(),
                auth=get_jira_auth(),
                verify=False
            )
            response.raise_for_status()
        
        # Handle status transition
        if status:
            # First, get available transitions
            trans_url = f"{JIRA_URL}/rest/api/3/issue/{issue_key}/transitions"
            trans_response = requests.get(
                trans_url,
                headers=get_headers(),
                auth=get_jira_auth(),
                verify=False
            )
            trans_response.raise_for_status()
            transitions = trans_response.json().get("transitions", [])
            
            # Find matching transition
            target_transition = None
            for t in transitions:
                if t.get("name", "").lower() == status.lower():
                    target_transition = t
                    break
            
            if target_transition:
                # Perform transition
                response = requests.post(
                    trans_url,
                    json={"transition": {"id": target_transition["id"]}},
                    headers=get_headers(),
                    auth=get_jira_auth(),
                    verify=False
                )
                response.raise_for_status()
                updates_made.append(f"status -> {status}")
            else:
                available = [t.get("name") for t in transitions]
                return json.dumps({
                    "error": f"Status '{status}' not available. Available transitions: {available}"
                })
        
        return json.dumps({
            "success": True,
            "key": issue_key,
            "updates": updates_made,
            "message": f"Updated {issue_key}: {', '.join(updates_made)}"
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def search_jira_projects() -> str:
    """
    List all JIRA projects accessible to the user.
    
    Returns:
        JSON string with list of projects
    """
    if not all([JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN]):
        return json.dumps({"error": "JIRA not configured."})
    
    try:
        api_url = f"{JIRA_URL}/rest/api/3/project"
        
        response = requests.get(
            api_url,
            headers=get_headers(),
            auth=get_jira_auth(),
            verify=False
        )
        response.raise_for_status()
        projects = response.json()
        
        result = []
        for p in projects:
            result.append({
                "key": p.get("key"),
                "name": p.get("name"),
                "id": p.get("id")
            })
        
        return json.dumps({"projects": result}, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    # Disable SSL warnings for development
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Run the server
    mcp.run()
