import os
import time
from fastapi import FastAPI, HTTPException, File, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
import requests
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
POLL_INTERVAL = 5      # ثواني بين كل محاولة
POLL_TIMEOUT = 60      # مهلة إجمالية بالثواني

@app.get("/")
async def root():
    return {"message": "مرحبًا! انتقل إلى /analyze-url لفحص الروابط أو /analyze-file لفحص الملفات"}

@app.post("/analyze-url")
async def analyze_url(url: str = Body(..., embed=True)):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    # 1) أرسل الطلب الأولي للحصول على analysis_id
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}
        )
        submit.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(400, f"فشل الاتصال ب-VirusTotal: {e}")

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نحصل على analysis_id")

    # 2) قم بعمل polling حتى يكتمل الفحص أو تنتهي المهلة
    elapsed = 0
    while elapsed < POLL_TIMEOUT:
        try:
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            report.raise_for_status()
            body = report.json()
            status = body.get("data", {}).get("attributes", {}).get("status")
        except requests.RequestException as e:
            raise HTTPException(400, f"فشل في جلب التقرير: {e}")

        if status == "completed":
            return body

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    raise HTTPException(504, "انتهت المهلة قبل اكتمال الفحص")

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    # نفس المنهجية: إرسال، ثم polling
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        files = {"file": (file.filename, file.file, file.content_type)}
        submit = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
        submit.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(400, f"فشل الاتصال ب-VirusTotal: {e}")

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نجِب analysis_id")

    elapsed = 0
    while elapsed < POLL_TIMEOUT:
        try:
            report = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            report.raise_for_status()
            body = report.json()
            status = body.get("data", {}).get("attributes", {}).get("status")
        except requests.RequestException as e:
            raise HTTPException(400, f"فشل في جلب التقرير: {e}")

        if status == "completed":
            return body

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    raise HTTPException(504, "انتهت المهلة قبل اكتمال فحص الملف")

# مسار بديل متوافق مع Flutter
@app.post("/scan-file")
async def scan_file_alias(file: UploadFile = File(...)):
    return await analyze_file(file)

@app.get("/test")
async def test():
    return {"message": "الـ API يعمل!"}
