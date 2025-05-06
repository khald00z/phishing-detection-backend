# main.py
import os
import uvicorn
from fastapi import FastAPI, HTTPException, File, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from dotenv import load_dotenv

# تحميل متغيرات البيئة من ملف .env
load_dotenv()

# تهيئة تطبيق FastAPI
app = FastAPI()

# تمكين CORS للتواصل مع تطبيق Flutter
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# الحصول على مفتاح VirusTotal API بشكل صحيح
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# نقطة نهاية للصفحة الرئيسية
@app.get("/")
async def root():
    return {"message": "مرحبًا! انتقل إلى /analyze-url لفحص الروابط أو /analyze-file لفحص الملفات"}

@app.post("/analyze-url")
async def analyze_url(url: str = Body(..., embed=True)):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        # إرسال الرابط إلى VirusTotal
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        submit_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=400,
            detail=f"فشل الاتصال ب VirusTotal: {str(e)}"
        )
    
    analysis_data = submit_response.json()
    analysis_id = analysis_data.get("data", {}).get("id")
    
    if not analysis_id:
        raise HTTPException(
            status_code=500,
            detail="لم يتم الحصول على analysis_id بشكل صحيح"
        )
    
    try:
        # جلب تقرير التحليل
        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        report_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=400,
            detail=f"فشل في الحصول على التقرير: {str(e)}"
        )
    
    return report_response.json()

@app.post("/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        # إرسال الملف إلى VirusTotal
        files = {"file": (file.filename, file.file, file.content_type)}
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files
        )
        submit_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=400,
            detail=f"فشل الاتصال ب VirusTotal: {str(e)}"
        )
    
    analysis_data = submit_response.json()
    analysis_id = analysis_data.get("data", {}).get("id")
    
    if not analysis_id:
        raise HTTPException(
            status_code=500,
            detail="لم يتم الحصول على analysis_id بشكل صحيح"
        )
    
    try:
        # جلب تقرير التحليل
        report_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )
        report_response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=400,
            detail=f"فشل في الحصول على التقرير: {str(e)}"
        )
    
    return report_response.json()

# مسار بديل متوافق مع Flutter
@app.post("/scan-file")
async def scan_file_alias(file: UploadFile = File(...)):
    return await analyze_file(file)

@app.get("/test")
async def test():
    return {"message": "الـ API يعمل!"}
