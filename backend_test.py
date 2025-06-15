#!/usr/bin/env python3
import requests
import json
import sys
import time
from datetime import datetime

# Base URL from frontend/.env
BASE_URL = "https://720b603b-d926-428d-8beb-8a58d96da08f.preview.emergentagent.com"
API_BASE_URL = f"{BASE_URL}/api"

def test_api_health():
    """Test the basic API health check endpoint"""
    print("\n=== Testing API Health Check ===")
    try:
        response = requests.get(f"{API_BASE_URL}/")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert "message" in response.json(), "Response missing 'message' field"
        assert "version" in response.json(), "Response missing 'version' field"
        assert response.json()["message"] == "Android Vulnerability Scanner API", f"Unexpected message: {response.json()['message']}"
        
        print("✅ API Health Check Test Passed")
        return True
    except Exception as e:
        print(f"❌ API Health Check Test Failed: {str(e)}")
        return False

def test_stats_endpoint():
    """Test the stats endpoint"""
    print("\n=== Testing Stats Endpoint ===")
    try:
        response = requests.get(f"{API_BASE_URL}/stats")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        
        # Check for required fields in the response
        required_fields = ["total_scans", "completed_scans", "failed_scans", "pending_scans"]
        for field in required_fields:
            assert field in response.json(), f"Response missing '{field}' field"
            assert isinstance(response.json()[field], int), f"'{field}' should be an integer"
        
        # Check for severity distribution (may be empty if no scans)
        assert "severity_distribution" in response.json(), "Response missing 'severity_distribution' field"
        assert isinstance(response.json()["severity_distribution"], dict), "'severity_distribution' should be a dictionary"
        
        print("✅ Stats Endpoint Test Passed")
        return True
    except Exception as e:
        print(f"❌ Stats Endpoint Test Failed: {str(e)}")
        return False

def test_scans_endpoint():
    """Test the scans endpoint"""
    print("\n=== Testing Scans Endpoint ===")
    try:
        response = requests.get(f"{API_BASE_URL}/scans")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"
        assert isinstance(response.json(), list), "Response should be a list"
        
        # If there are scans, check the structure of the first scan
        if len(response.json()) > 0:
            scan = response.json()[0]
            required_fields = ["id", "file_name", "file_size", "app_info", "scan_status", "scan_time"]
            for field in required_fields:
                assert field in scan, f"Scan missing '{field}' field"
            
            # Check app_info structure
            assert "package_name" in scan["app_info"], "app_info missing 'package_name' field"
        
        print("✅ Scans Endpoint Test Passed")
        return True
    except Exception as e:
        print(f"❌ Scans Endpoint Test Failed: {str(e)}")
        return False

def run_all_tests():
    """Run all tests and return overall result"""
    print(f"Starting Android Vulnerability Scanner API Tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Testing API at: {API_BASE_URL}")
    
    test_results = {
        "api_health": test_api_health(),
        "stats_endpoint": test_stats_endpoint(),
        "scans_endpoint": test_scans_endpoint()
    }
    
    # Print summary
    print("\n=== Test Summary ===")
    for test_name, result in test_results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")
    
    # Overall result
    all_passed = all(test_results.values())
    print(f"\nOverall Result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    
    return all_passed

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)