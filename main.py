import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import time
import random
import requests
from sklearn.ensemble import IsolationForest
from security_rules import DANGEROUS_PATTERNS

# --- Core Data Definitions ---
USERS = [
    "Alice Chen", "Bob Smith", "Charlie Davis", "Diana Prince", "Evan Wright", 
    "Fiona Gallagher", "George Martin", "Hannah Abbott", "Ian Malcolm", "Jessica Jones",
    "Kevin Flynn", "Laura Kinney", "Marcus Cole", "Nina Sharp", "Oliver Queen"
]

# Tracking all 3 Apps
APPS = ["Company Portal", "Database System", "GitHub Enterprise"]

class LogEntry(BaseModel):
    username: str
    app: str
    ip_address: str
    location: str
    timestamp: int 
    action: str
    status: str 

class AdminAction(BaseModel):
    target: str 
    action: str 

# --- State Management ---
logs_db = []
alerts_db = []
online_users = set()
blacklisted_ips = set()
auth_stats = {"success": 0, "failed": 0} 

# NEW: Tracks history, actions, and anomalies for scorecards and traceback
user_profiles = {
    user: {
        "last_location": None, 
        "last_ip": None, 
        "last_time": 0, 
        "file_access_revoked": False,
        "total_actions": 0,
        "anomalies": 0,
        "history": []
    }
    for user in USERS
}
app_stats = {app: {"logs": 0, "alerts": 0} for app in APPS}

active_sessions = {user: set() for user in USERS}

# --- Machine Learning Setup ---
ACTIONS = {"login": 0, "logout": 1, "file_access": 2, "sensitive_access": 3, "upload_code": 4}
LOCATIONS = {"US": 0, "UK": 1, "CA": 2, "RU": 10, "CN": 10, "KP": 15}

X_train = []
for _ in range(500):
    app_choice = random.choice([0, 1, 2])
    if app_choice == 2: act = random.choice([0, 4]) 
    else: act = random.choice([0, 2]) 
    X_train.append([random.randint(9, 17), random.choice([0, 1]), app_choice, act, 0])

clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
clf.fit(X_train)

def analyze_behavior(log: LogEntry):
    profile = user_profiles.get(log.username)
    reasons = []
    is_anomaly = False
    risk_score = 0.0
    
    hour = time.localtime(log.timestamp).tm_hour
    loc_enc = LOCATIONS.get(log.location, 5)
    app_enc = APPS.index(log.app) if log.app in APPS else 0
    act_enc = ACTIONS.get(log.action, 0)
    stat_enc = 50 if log.status == "failed" else 0
    
    features = [[hour, loc_enc, app_enc, act_enc, stat_enc]]
    prediction = clf.predict(features)[0]

    if log.ip_address in blacklisted_ips:
        return {"status": "anomaly", "risk_score": 99.9, "reasons": ["BLOCKED: Connection from Blacklisted IP"]}

    if profile["file_access_revoked"] and "access" in log.action:
        return {"status": "anomaly", "risk_score": 99.0, "reasons": ["CRITICAL: Attempted file access by revoked user!"]}

    if profile["last_location"] and profile["last_location"] != log.location:
        time_diff = log.timestamp - profile["last_time"]
        if time_diff < 3600: 
            blacklisted_ips.add(log.ip_address) 
            reasons.append(f"IMPOSSIBLE TRAVEL: Jumped from {profile['last_location']} to {log.location}. IP Auto-Blocked.")
            is_anomaly = True
            risk_score = 95.0
    
    contributions = {
        "Time": abs(hour - 13) / 12,
        "Location": 1.0 if loc_enc > 2 else 0.1,
        "App": 0.2, 
        "Action": 1.0 if log.action == "sensitive_access" else 0.2,
        "Status": 1.0 if log.status == "failed" else 0.0
    }

    if prediction == -1 or log.status == "failed" or log.action == "sensitive_access":
        is_anomaly = True
        summary = f"{log.username} triggered a high-risk alert on {log.app}."
        if log.status == "failed": 
            summary = f"Security blocked {log.username} after a failed credential match."
        elif log.location == "RU": 
            summary = f"Access attempt from a high-risk geo-zone ({log.location}) detected."
        elif hour < 7 or hour > 19:
            summary = f"User active during non-business hours ({hour}:00), suggesting compromised credentials."
        
        reasons.append(summary)
        risk_score = max(80.0 if log.status == "failed" else 60.0, 40.0)

    return {
        "status": "anomaly" if is_anomaly else "normal",
        "risk_score": risk_score,
        "reasons": reasons,
        "xai_scores": contributions 
    }

# ==========================================
# BACKGROUND SIMULATOR ENGINE
# ==========================================
def generate_simulated_log():
    is_anomaly_demo = random.random() < 0.25
    username = random.choice(USERS)
    app_name = random.choice(APPS)
    
    log_data = {
        "username": username,
        "app": app_name,
        "ip_address": f"192.168.1.{random.randint(1, 255)}",
        "location": "US" if random.random() > 0.5 else "UK",
        "timestamp": int(time.time()),
        "action": "upload_code" if app_name == "GitHub Enterprise" else "file_access",
        "status": "success"
    }

    if app_name not in active_sessions[username]:
        log_data["action"] = "login"
    elif random.random() > 0.8:
        log_data["action"] = "logout"

    if is_anomaly_demo:
        scenario = random.randint(0, 2)
        if scenario == 0: log_data["action"] = "sensitive_access"
        elif scenario == 1: 
            log_data["location"] = "RU"
            log_data["ip_address"] = "45.12.33.102"
        elif scenario == 2: 
            log_data["status"] = "failed"
            log_data["action"] = "login"

    if log_data["status"] == "success":
        if log_data["action"] == "login": active_sessions[username].add(app_name)
        elif log_data["action"] == "logout": active_sessions[username].discard(app_name)

    receive_log(LogEntry(**log_data))

async def background_log_generator():
    while True:
        generate_simulated_log()
        await asyncio.sleep(10)

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(background_log_generator())
    yield
    task.cancel() 

app = FastAPI(title="Sentinel SIEM API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# DevSecOps: SAST Scanner Engine
# ==========================================
def scan_code_for_threats(code_content: str):
    detected_threats = []
    lines = code_content.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern, warning in DANGEROUS_PATTERNS.items():
            if pattern in line:
                detected_threats.append(f"Line {line_num}: {warning} ['{pattern}' detected]")
    return detected_threats

@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.json()
    if "commits" in payload:
        repo_name = payload["repository"]["full_name"]
        pusher = payload.get("pusher", {}).get("name", "Unknown Developer")
        for commit in payload["commits"]:
            files_to_check = commit.get("added", []) + commit.get("modified", [])
            for file_path in files_to_check:
                if file_path.endswith((".html", ".js")):
                    raw_url = f"https://raw.githubusercontent.com/{repo_name}/{commit['id']}/{file_path}"
                    response = requests.get(raw_url)
                    if response.status_code == 200:
                        code_content = response.text
                        threats = scan_code_for_threats(code_content)
                        if threats:
                            alert_data = {
                                "username": pusher,
                                "app": "GitHub Enterprise",
                                "ip_address": "GitHub Actions",
                                "location": "Cloud",
                                "timestamp": int(time.time()),
                                "action": "upload_code",
                                "status": "success",
                                "analysis": {
                                    "status": "anomaly",
                                    "risk_score": 98.5,
                                    "reasons": [f"CRITICAL SAST ALERT in {file_path}:"] + threats,
                                    "xai_scores": {"Action": 0.9, "App": 0.1} 
                                }
                            }
                            alerts_db.insert(0, alert_data)
                            app_stats["GitHub Enterprise"]["alerts"] += 1
                            
    return {"message": "Webhook processed successfully"}

# --- API Endpoints ---
@app.post("/log")
def receive_log(log: LogEntry):
    analysis = analyze_behavior(log)
    
    if log.action == "login":
        if log.status == "success": auth_stats["success"] += 1
        else: auth_stats["failed"] += 1

    if log.status == "success" and log.action == "login" and analysis["status"] != "anomaly": 
        online_users.add(log.username)
    elif log.action == "logout" and log.username in online_users: 
        online_users.remove(log.username)
    
    if log.app in app_stats:
        app_stats[log.app]["logs"] += 1
        if analysis["status"] == "anomaly": 
            app_stats[log.app]["alerts"] += 1

    # --- NEW: Track User History & Scoring ---
    profile = user_profiles.get(log.username)
    if profile:
        profile["total_actions"] += 1
        if analysis["status"] == "anomaly":
            profile["anomalies"] += 1
        
        # Save exact snapshot of this log for the forensic timeline
        history_entry = log.model_dump()
        history_entry["analysis"] = analysis
        profile["history"].append(history_entry)
        profile["history"] = profile["history"][-10:] # Keep only the last 10

    log_data = log.model_dump()
    log_data["analysis"] = analysis
    logs_db.insert(0, log_data)
    if analysis["status"] == "anomaly": 
        alerts_db.insert(0, log_data)
        
    return {"message": "Log processed", "analysis": analysis}

@app.get("/stats")
def get_stats():
    # NEW: Calculate Gamified Cyber Hygiene Leaderboard
    user_scores = []
    for user, data in user_profiles.items():
        score = 100
        if data["total_actions"] > 0:
            penalty = (data["anomalies"] / data["total_actions"]) * 100 * 2 
            score = max(0, int(100 - penalty))
        
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "F"
        user_scores.append({"username": user, "score": score, "grade": grade})
    
    user_scores.sort(key=lambda x: x["score"], reverse=True)

    return {
        "total_users": len(USERS), 
        "online_users": len(online_users), 
        "app_stats": app_stats, 
        "auth_stats": auth_stats,
        "recent_logs": logs_db[:15], 
        "recent_alerts": alerts_db[:5],
        "leaderboard": user_scores # NEW: Send to frontend
    }

# NEW: Forensic Timeline Endpoint
@app.get("/traceback/{username}")
def get_traceback(username: str):
    return user_profiles.get(username, {}).get("history", [])

@app.get("/admin/users")
def get_admin_data():
    return {"profiles": user_profiles, "blacklisted_ips": list(blacklisted_ips), "online_users": list(online_users)}

@app.post("/admin/action")
def perform_admin_action(req: AdminAction):
    if req.action == "revoke_access" and req.target in user_profiles: 
        user_profiles[req.target]["file_access_revoked"] = True
    elif req.action == "restore_access" and req.target in user_profiles: 
        user_profiles[req.target]["file_access_revoked"] = False
    elif req.action == "blacklist_ip": 
        blacklisted_ips.add(req.target)
    elif req.action == "whitelist_ip" and req.target in blacklisted_ips: 
        blacklisted_ips.remove(req.target)
    return {"message": "Success"}

# ==========================================
# FRONTEND FILE SERVING ROUTES
# ==========================================
@app.get("/")
@app.get("/index.html")
def serve_dashboard(): return FileResponse("index.html")

@app.get("/admin.html")
def serve_admin(): return FileResponse("admin.html")

@app.get("/favicon.ico")
def serve_favicon(): return {"message": "No favicon"}

@app.get("/devsecops.html")
def serve_devsecops(): return FileResponse("devsecops.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)