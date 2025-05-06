import os
import time
from fastapi import FastAPI, HTTPException, File, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
import requests
from dotenv import load_dotenv

# === تحميل متغيّرات البيئة ===
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("VIRUSTOTAL_API_KEY غير مُعرّف في .env")

# === ثوابت الـ polling (قابل للضبط) ===
POLL_INTERVAL = 3       # segundos بين كل محاولة
POLL_TIMEOUT  = 60      # إجمالي المهلة بالثواني

# === تهيئة الفاستAPI وCORS ===
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "مرحبًا! استخدم /analyze-url أو /analyze-file"}

def _poll_report(report_url: str, headers: dict):
    """تنفّذ جولة polling حتى يكتمل التحليل أو ينتهي الوقت."""
    start = time.time()
    while True:
        resp = requests.get(report_url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        status = data.get("data", {}).get("attributes", {}).get("status")
        # الحالة قد تكون "queued" أو "running" أو "completed"
        if status == "completed":
            return data
        if time.time() - start > POLL_TIMEOUT:
            raise HTTPException(504, "انتهت مهلة polling دون الحصول على نتيجة.")
        time.sleep(POLL_INTERVAL)

@app.post("/analyze-url")
async def analyze_url(url: str = Body(..., embed=True)):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # 1) إرسال الرابط
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        submit.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(400, f"فشل في إرسال الرابط: {e}")
    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نحصل على analysis_id من VirusTotal.")
    # 2) polling للحصول على التقرير
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    return _poll_report(report_url, headers)

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # 1) رفع الملف
    try:
        files = {"file": (file.filename, file.file, file.content_type)}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files
        )
        submit.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(400, f"فشل في رفع الملف: {e}")
    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نحصل على analysis_id من VirusTotal.")
    # 2) polling للتقرير
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    return _poll_report(report_url, headers)

# alias لمن يريد /scan-file
@app.post("/scan-file")
async def scan_file_alias(file: UploadFile = File(...)):
    return await analyze_file(file)

@app.get("/test")
async def test():
    return {"message": "الـ API يعمل!"}
