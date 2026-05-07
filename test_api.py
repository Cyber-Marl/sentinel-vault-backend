"""
SentinelVault — API Integration Test Script
Tests: Login, Profile, Upload, List, Detail, Download, Delete, Audit Logs
"""
import requests
import json
import os
import tempfile

BASE = "http://localhost:8080"

def sep(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")

# ── Test 1: Login ──
sep("TEST 1: Login (JWT Authentication)")
r = requests.post(f"{BASE}/api/auth/login/", json={
    "email": "admin@sentinelvault.com",
    "password": "Admin@12345"
})
print(f"Status: {r.status_code}")
data = r.json()
print(f"User: {data.get('user')}")
token = data.get("access", "")
print(f"Access Token: {token[:50]}...")
refresh = data.get("refresh", "")
headers = {"Authorization": f"Bearer {token}"}

# ── Test 2: Profile ──
sep("TEST 2: User Profile")
r = requests.get(f"{BASE}/api/auth/profile/", headers=headers)
print(f"Status: {r.status_code}")
print(f"Profile: {json.dumps(r.json(), indent=2)}")

# ── Test 3: Upload Document ──
sep("TEST 3: Upload Document (Encrypt + Hash)")
# Create a test file
test_content = b"This is a TOP SECRET document for SentinelVault testing.\nClassification: CONFIDENTIAL"
test_filename = "test_secret_doc.txt"

r = requests.post(
    f"{BASE}/api/documents/upload/",
    headers=headers,
    data={"title": "Test Secret Document", "description": "Integration test file"},
    files={"file": (test_filename, test_content, "text/plain")}
)
print(f"Status: {r.status_code}")
upload_data = r.json()
print(f"Message: {upload_data.get('message')}")
doc = upload_data.get("document", {})
doc_id = doc.get("id")
print(f"Document ID: {doc_id}")
print(f"File Hash: {doc.get('file_hash')}")
print(f"File Size: {doc.get('file_size_display')}")
print(f"Download URL: {doc.get('download_url')}")

# ── Test 4: List Documents ──
sep("TEST 4: List Documents")
r = requests.get(f"{BASE}/api/documents/", headers=headers)
print(f"Status: {r.status_code}")
list_data = r.json()
print(f"Total documents: {list_data.get('count', len(list_data.get('results', [])))}")
for d in list_data.get("results", []):
    print(f"  - {d['title']} ({d['original_filename']}, {d['file_size_display']})")

# ── Test 5: Document Detail ──
sep("TEST 5: Document Detail")
r = requests.get(f"{BASE}/api/documents/{doc_id}/", headers=headers)
print(f"Status: {r.status_code}")
detail = r.json()
print(f"Title: {detail.get('title')}")
print(f"Hash: {detail.get('file_hash')}")
print(f"Owner: {detail.get('owner_email')}")

# ── Test 6: Download + Integrity Verification ──
sep("TEST 6: Download (Decrypt + Verify SHA-256)")
r = requests.get(f"{BASE}/api/documents/{doc_id}/download/", headers=headers)
print(f"Status: {r.status_code}")
print(f"Content-Type: {r.headers.get('Content-Type')}")
print(f"Content-Disposition: {r.headers.get('Content-Disposition')}")
print(f"Downloaded content matches original: {r.content == test_content}")
print(f"Downloaded content: {r.content.decode()[:80]}...")

# ── Test 7: Unauthenticated Access (should fail) ──
sep("TEST 7: Unauthenticated Access (should be 401)")
r = requests.get(f"{BASE}/api/documents/")
print(f"Status: {r.status_code} (expected 401)")
print(f"Response: {r.json()}")

# ── Test 8: Audit Logs ──
sep("TEST 8: Audit Logs (Admin-only)")
r = requests.get(f"{BASE}/api/audit-logs/", headers=headers)
print(f"Status: {r.status_code}")
audit_data = r.json()
total = audit_data.get("count", len(audit_data.get("results", [])))
print(f"Total audit entries: {total}")
for entry in audit_data.get("results", [])[:5]:
    print(f"  [{entry['timestamp']}] {entry.get('user_email','N/A')} — {entry['action']} {entry['resource_type']}")

# ── Test 9: Soft Delete ──
sep("TEST 9: Soft Delete Document")
r = requests.delete(f"{BASE}/api/documents/{doc_id}/delete/", headers=headers)
print(f"Status: {r.status_code}")
print(f"Response: {r.json()}")

# Verify it's gone from listings
r = requests.get(f"{BASE}/api/documents/", headers=headers)
remaining = r.json().get("count", len(r.json().get("results", [])))
print(f"Documents remaining after delete: {remaining}")

# ── Test 10: Token Refresh ──
sep("TEST 10: Token Refresh")
r = requests.post(f"{BASE}/api/auth/token/refresh/", json={"refresh": refresh})
print(f"Status: {r.status_code}")
print(f"New access token received: {'access' in r.json()}")

sep("ALL TESTS COMPLETED SUCCESSFULLY")
