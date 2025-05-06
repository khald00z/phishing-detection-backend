import time
import os
import requests
from fastapi import FastAPI, HTTPException, File, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# تحميل متغيرات البيئة من ملف .env
load_dotenv()

# تهيئة تطبيق FastAPI
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# مفتاح API
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("VIRUSTOTAL_API_KEY not set in .env")

HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}


@app.get("/")
async def root():
    return {"message": "مرحبًا! استخدم /analyze-url أو /analyze-file أو /scan-file"}


@app.post("/analyze-url")
async def analyze_url(url: str = Body(..., embed=True)):
    # 1) إرسال الرابط
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=HEADERS,
            data={"url": url}
        )
        submit.raise_for_status()
    except Exception as e:
        raise HTTPException(400, f"فشل إرسال الرابط: {e}")

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نستطع الحصول على analysis_id")

    # 2) Polling: انتظر انتهاء التحليل (حتى 30 ثانية)
    for _ in range(30):
        status_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=HEADERS
        )
        status_resp.raise_for_status()
        status = status_resp.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(1)
    else:
        raise HTTPException(504, "انتهى وقت الانتظار قبل انتهاء التحليل")

    # 3) جلب التقرير المجمّع النهائي
    try:
        report = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{analysis_id}",
            headers=HEADERS
        )
        report.raise_for_status()
    except Exception as e:
        raise HTTPException(400, f"فشل جلب التقرير النهائي: {e}")

    stats = report.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    verdict = (
        "malicious" if stats.get("malicious", 0) > 0 else
        "suspicious" if stats.get("suspicious", 0) > 0 else
        "harmless"
    )
    return {
        "url": url,
        "stats": stats,
        "verdict": verdict
    }


@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    # فحص ملف
    try:
        files = {"file": (file.filename, file.file, file.content_type)}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=HEADERS,
            files=files
        )
        submit.raise_for_status()
    except Exception as e:
        raise HTTPException(400, f"فشل إرسال الملف: {e}")

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        raise HTTPException(500, "لم نستطع الحصول على analysis_id للملف")

    # Polling
    for _ in range(30):
        status_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=HEADERS
        )
        status_resp.raise_for_status()
        status = status_resp.json().get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(1)
    else:
        raise HTTPException(504, "انتهى وقت الانتظار قبل انتهاء تحليل الملف")

    try:
        report = requests.get(
            f"https://www.virustotal.com/api/v3/files/{analysis_id}",
            headers=HEADERS
        )
        report.raise_for_status()
    except Exception as e:
        raise HTTPException(400, f"فشل جلب تقرير الملف: {e}")

    stats = report.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    verdict = (
        "malicious" if stats.get("malicious", 0) > 0 else
        "suspicious" if stats.get("suspicious", 0) > 0 else
        "harmless"
    )
    return {
        "filename": file.filename,
        "stats": stats,
        "verdict": verdict
    }


# alias لـ Flutter
@app.post("/scan-file")
async def scan_file_alias(file: UploadFile = File(...)):
    return await analyze_file(file)


@app.get("/test")
async def test():
    return {"message": "Your Server is live 🎉"}
