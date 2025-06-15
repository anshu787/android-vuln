from fastapi import FastAPI, APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import zipfile
import tempfile
import subprocess
import json
import xml.etree.ElementTree as ET
import re
import aiofiles
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="Android Vulnerability Scanner", description="Advanced APK analysis and vulnerability detection")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Data Models
class VulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: str  # HIGH, MEDIUM, LOW, INFO
    category: str  # MANIFEST, CODE, CRYPTO, PERMISSIONS, etc.
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None

class AppInfo(BaseModel):
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk_version: Optional[str] = None
    target_sdk_version: Optional[str] = None
    permissions: List[str] = []
    activities: List[str] = []
    services: List[str] = []
    receivers: List[str] = []
    providers: List[str] = []

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_name: str
    file_size: int
    app_info: AppInfo
    findings: List[VulnerabilityFinding] = []
    scan_status: str = "PENDING"  # PENDING, SCANNING, COMPLETED, FAILED
    scan_time: datetime = Field(default_factory=datetime.utcnow)
    completion_time: Optional[datetime] = None
    error_message: Optional[str] = None

class ScanCreate(BaseModel):
    file_name: str
    file_size: int

# Vulnerability Analysis Engine
class AndroidAnalysisEngine:
    def __init__(self):
        self.jadx_path = "/app/tools/jadx/bin/jadx"
        self.apktool_path = "/usr/local/bin/apktool"
        
    async def analyze_apk(self, apk_path: str, scan_id: str) -> ScanResult:
        """Main APK analysis function"""
        findings = []
        app_info = None
        
        try:
            # Update scan status
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"scan_status": "SCANNING"}}
            )
            
            # Create temporary directory for analysis
            with tempfile.TemporaryDirectory() as temp_dir:
                manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                
                # Extract AndroidManifest.xml using apktool
                await self._extract_manifest(apk_path, temp_dir)
                
                # Parse AndroidManifest.xml
                app_info = await self._parse_manifest(manifest_path)
                
                # Analyze manifest for vulnerabilities
                manifest_findings = await self._analyze_manifest(manifest_path)
                findings.extend(manifest_findings)
                
                # Decompile APK for code analysis
                decompiled_dir = os.path.join(temp_dir, "decompiled")
                await self._decompile_apk(apk_path, decompiled_dir)
                
                # Analyze Java code for vulnerabilities
                code_findings = await self._analyze_code(decompiled_dir)
                findings.extend(code_findings)
                
                # Check for CVEs (mock implementation for now)
                cve_findings = await self._check_cves(app_info)
                findings.extend(cve_findings)
                
        except Exception as e:
            logger.error(f"Error analyzing APK {scan_id}: {str(e)}")
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {"scan_status": "FAILED", "error_message": str(e)}}
            )
            raise
        
        return findings, app_info
    
    async def _extract_manifest(self, apk_path: str, output_dir: str):
        """Extract AndroidManifest.xml using apktool"""
        cmd = [self.apktool_path, "d", "-o", output_dir, "-f", apk_path]
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Apktool failed: {stderr.decode()}")
    
    async def _parse_manifest(self, manifest_path: str) -> AppInfo:
        """Parse AndroidManifest.xml and extract app information"""
        if not os.path.exists(manifest_path):
            raise Exception("AndroidManifest.xml not found")
        
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Extract basic app info
        package_name = root.get('package', 'unknown')
        version_name = root.get('{http://schemas.android.com/apk/res/android}versionName')
        version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode')
        
        # Extract SDK versions
        uses_sdk = root.find('uses-sdk')
        min_sdk = None
        target_sdk = None
        if uses_sdk is not None:
            min_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
            target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
        
        # Extract permissions
        permissions = []
        for perm in root.findall('uses-permission'):
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
            if perm_name:
                permissions.append(perm_name)
        
        # Extract components
        activities = []
        services = []
        receivers = []
        providers = []
        
        app_element = root.find('application')
        if app_element is not None:
            for activity in app_element.findall('activity'):
                name = activity.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    activities.append(name)
            
            for service in app_element.findall('service'):
                name = service.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    services.append(name)
            
            for receiver in app_element.findall('receiver'):
                name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    receivers.append(name)
            
            for provider in app_element.findall('provider'):
                name = provider.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    providers.append(name)
        
        return AppInfo(
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk_version=min_sdk,
            target_sdk_version=target_sdk,
            permissions=permissions,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers
        )
    
    async def _analyze_manifest(self, manifest_path: str) -> List[VulnerabilityFinding]:
        """Analyze AndroidManifest.xml for security vulnerabilities"""
        findings = []
        
        if not os.path.exists(manifest_path):
            return findings
        
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Check for dangerous permissions
        dangerous_perms = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.WRITE_EXTERNAL_STORAGE'
        ]
        
        for perm in root.findall('uses-permission'):
            perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
            if perm_name in dangerous_perms:
                findings.append(VulnerabilityFinding(
                    severity="MEDIUM",
                    category="PERMISSIONS",
                    title=f"Dangerous Permission: {perm_name}",
                    description=f"App requests dangerous permission {perm_name} which could be misused",
                    file_path="AndroidManifest.xml",
                    remediation="Ensure this permission is necessary and implement proper access controls"
                ))
        
        # Check for exported components without protection
        app_element = root.find('application')
        if app_element is not None:
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for component in app_element.findall(component_type):
                    exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                    permission = component.get('{http://schemas.android.com/apk/res/android}permission')
                    
                    if exported == "true" and not permission:
                        comp_name = component.get('{http://schemas.android.com/apk/res/android}name', 'unknown')
                        findings.append(VulnerabilityFinding(
                            severity="HIGH",
                            category="MANIFEST",
                            title=f"Unprotected Exported {component_type.title()}",
                            description=f"Exported {component_type} '{comp_name}' lacks permission protection",
                            file_path="AndroidManifest.xml",
                            remediation=f"Add permission attribute to protect this {component_type}"
                        ))
            
            # Check for debug mode
            debuggable = app_element.get('{http://schemas.android.com/apk/res/android}debuggable')
            if debuggable == "true":
                findings.append(VulnerabilityFinding(
                    severity="HIGH",
                    category="MANIFEST",
                    title="Debug Mode Enabled",
                    description="Application is debuggable in production",
                    file_path="AndroidManifest.xml",
                    remediation="Remove android:debuggable attribute or set to false for production"
                ))
            
            # Check for backup allowance
            allow_backup = app_element.get('{http://schemas.android.com/apk/res/android}allowBackup')
            if allow_backup == "true" or allow_backup is None:
                findings.append(VulnerabilityFinding(
                    severity="MEDIUM",
                    category="MANIFEST",
                    title="Backup Allowed",
                    description="Application data can be backed up via ADB",
                    file_path="AndroidManifest.xml",
                    remediation="Set android:allowBackup to false to prevent data leakage"
                ))
        
        return findings
    
    async def _decompile_apk(self, apk_path: str, output_dir: str):
        """Decompile APK using jadx"""
        cmd = [self.jadx_path, "-d", output_dir, apk_path]
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            logger.warning(f"Jadx decompilation warnings: {stderr.decode()}")
    
    async def _analyze_code(self, decompiled_dir: str) -> List[VulnerabilityFinding]:
        """Analyze decompiled Java code for vulnerabilities"""
        findings = []
        
        if not os.path.exists(decompiled_dir):
            return findings
        
        # Search for common vulnerability patterns
        patterns = {
            "hardcoded_secrets": {
                "pattern": r'(password|key|secret|token)\s*=\s*["\'][^"\']{8,}["\']',
                "severity": "HIGH",
                "title": "Hardcoded Secret",
                "description": "Potential hardcoded password, key, or secret found"
            },
            "crypto_weak": {
                "pattern": r'(DES|RC4|MD5|SHA1)(?![a-zA-Z])',
                "severity": "MEDIUM", 
                "title": "Weak Cryptographic Algorithm",
                "description": "Usage of weak cryptographic algorithm detected"
            },
            "webview_js": {
                "pattern": r'setJavaScriptEnabled\s*\(\s*true\s*\)',
                "severity": "MEDIUM",
                "title": "WebView JavaScript Enabled",
                "description": "WebView has JavaScript enabled which could be exploited"
            },
            "http_urls": {
                "pattern": r'http://[^\s"\'<>]+',
                "severity": "LOW",
                "title": "HTTP URL Usage",
                "description": "HTTP URL found, consider using HTTPS"
            }
        }
        
        # Walk through source files
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern_info in patterns.items():
                            matches = re.finditer(pattern_info["pattern"], content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                rel_path = os.path.relpath(file_path, decompiled_dir)
                                
                                findings.append(VulnerabilityFinding(
                                    severity=pattern_info["severity"],
                                    category="CODE",
                                    title=pattern_info["title"],
                                    description=f"{pattern_info['description']}: {match.group(0)}",
                                    file_path=rel_path,
                                    line_number=line_num,
                                    remediation="Review and fix the identified code pattern"
                                ))
                    except Exception as e:
                        logger.warning(f"Error analyzing file {file_path}: {str(e)}")
        
        return findings
    
    async def _check_cves(self, app_info: AppInfo) -> List[VulnerabilityFinding]:
        """Check for known CVEs (mock implementation)"""
        findings = []
        
        # Mock CVE checks based on SDK version and package name
        if app_info.target_sdk_version and int(app_info.target_sdk_version) < 23:
            findings.append(VulnerabilityFinding(
                severity="HIGH",
                category="CVE",
                title="Outdated Target SDK Version",
                description=f"Target SDK {app_info.target_sdk_version} is outdated and may contain known vulnerabilities",
                cve_id="CVE-2016-XXXX",
                remediation="Update target SDK version to the latest available"
            ))
        
        if app_info.min_sdk_version and int(app_info.min_sdk_version) < 21:
            findings.append(VulnerabilityFinding(
                severity="MEDIUM",
                category="CVE", 
                title="Low Minimum SDK Version",
                description=f"Minimum SDK {app_info.min_sdk_version} supports outdated Android versions",
                remediation="Consider raising minimum SDK version for better security"
            ))
        
        return findings

# Initialize analysis engine
analysis_engine = AndroidAnalysisEngine()

# Background task for APK analysis
async def process_apk_analysis(file_path: str, scan_id: str, file_name: str, file_size: int):
    """Background task to process APK analysis"""
    try:
        findings, app_info = await analysis_engine.analyze_apk(file_path, scan_id)
        
        # Update scan result in database
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "scan_status": "COMPLETED",
                "completion_time": datetime.utcnow(),
                "app_info": app_info.dict(),
                "findings": [f.dict() for f in findings]
            }}
        )
        
        logger.info(f"Scan {scan_id} completed with {len(findings)} findings")
        
    except Exception as e:
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "scan_status": "FAILED",
                "error_message": str(e),
                "completion_time": datetime.utcnow()
            }}
        )
        logger.error(f"Scan {scan_id} failed: {str(e)}")
    finally:
        # Clean up temporary file
        if os.path.exists(file_path):
            os.remove(file_path)

# API Endpoints
@api_router.get("/")
async def root():
    return {"message": "Android Vulnerability Scanner API", "version": "1.0"}

@api_router.post("/upload", response_model=ScanResult)
async def upload_apk(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload APK file for analysis"""
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Only APK files are allowed")
    
    # Create temporary file
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, f"{uuid.uuid4()}.apk")
    
    try:
        # Save uploaded file
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        file_size = len(content)
        
        # Create scan record
        scan_result = ScanResult(
            file_name=file.filename,
            file_size=file_size,
            app_info=AppInfo(package_name="pending"),
            scan_status="PENDING"
        )
        
        # Save to database
        await db.scans.insert_one(scan_result.dict())
        
        # Start background analysis
        background_tasks.add_task(
            process_apk_analysis, 
            file_path, 
            scan_result.id, 
            file.filename, 
            file_size
        )
        
        return scan_result
        
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@api_router.get("/scans", response_model=List[ScanResult])
async def get_scans():
    """Get all scan results"""
    scans = await db.scans.find().sort("scan_time", -1).to_list(100)
    return [ScanResult(**scan) for scan in scans]

@api_router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    """Get specific scan result"""
    scan = await db.scans.find_one({"id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**scan)

@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete scan result"""
    result = await db.scans.delete_one({"id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"message": "Scan deleted successfully"}

@api_router.get("/stats")
async def get_stats():
    """Get scanning statistics"""
    total_scans = await db.scans.count_documents({})
    completed_scans = await db.scans.count_documents({"scan_status": "COMPLETED"})
    failed_scans = await db.scans.count_documents({"scan_status": "FAILED"})
    pending_scans = await db.scans.count_documents({"scan_status": {"$in": ["PENDING", "SCANNING"]}})
    
    # Get severity distribution
    pipeline = [
        {"$match": {"scan_status": "COMPLETED"}},
        {"$unwind": "$findings"},
        {"$group": {"_id": "$findings.severity", "count": {"$sum": 1}}}
    ]
    severity_stats = await db.scans.aggregate(pipeline).to_list(10)
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "pending_scans": pending_scans,
        "severity_distribution": {item["_id"]: item["count"] for item in severity_stats}
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()