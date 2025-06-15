import React, { useState, useEffect } from 'react';
import './App.css';
import axios from 'axios';
import { 
  CloudArrowUpIcon, 
  ShieldCheckIcon, 
  ExclamationTriangleIcon,
  DocumentTextIcon,
  ClockIcon,
  XMarkIcon,
  EyeIcon,
  ChartBarIcon,
  TrashIcon
} from '@heroicons/react/24/outline';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const SeverityBadge = ({ severity }) => {
  const colors = {
    HIGH: 'bg-red-100 text-red-800 border-red-200',
    MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    LOW: 'bg-blue-100 text-blue-800 border-blue-200',
    INFO: 'bg-gray-100 text-gray-800 border-gray-200'
  };
  
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${colors[severity] || colors.INFO}`}>
      {severity}
    </span>
  );
};

const CategoryBadge = ({ category }) => {
  const colors = {
    MANIFEST: 'bg-purple-100 text-purple-800',
    CODE: 'bg-green-100 text-green-800',
    PERMISSIONS: 'bg-orange-100 text-orange-800',
    CVE: 'bg-red-100 text-red-800',
    CRYPTO: 'bg-indigo-100 text-indigo-800'
  };
  
  return (
    <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${colors[category] || 'bg-gray-100 text-gray-800'}`}>
      {category}
    </span>
  );
};

const StatusBadge = ({ status }) => {
  const config = {
    PENDING: { color: 'bg-yellow-100 text-yellow-800', icon: ClockIcon },
    SCANNING: { color: 'bg-blue-100 text-blue-800', icon: ClockIcon },
    COMPLETED: { color: 'bg-green-100 text-green-800', icon: ShieldCheckIcon },
    FAILED: { color: 'bg-red-100 text-red-800', icon: ExclamationTriangleIcon }
  };
  
  const { color, icon: Icon } = config[status] || config.PENDING;
  
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${color}`}>
      <Icon className="w-3 h-3 mr-1" />
      {status}
    </span>
  );
};

const UploadSection = ({ onUpload, uploading }) => {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.apk')) {
        onUpload(file);
      } else {
        alert('Please upload an APK file');
      }
    }
  };

  const handleFileInput = (e) => {
    if (e.target.files && e.target.files[0]) {
      onUpload(e.target.files[0]);
    }
  };

  return (
    <div className="mb-8">
      <div
        className={`relative border-2 border-dashed rounded-lg p-6 transition-colors ${
          dragActive ? 'border-blue-400 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="text-center">
          <CloudArrowUpIcon className="mx-auto h-12 w-12 text-gray-400" />
          <div className="mt-4">
            <label htmlFor="file-upload" className="cursor-pointer">
              <span className="mt-2 block text-sm font-medium text-gray-900">
                {uploading ? 'Uploading...' : 'Drop APK files here or click to browse'}
              </span>
              <input
                id="file-upload"
                name="file-upload"
                type="file"
                accept=".apk"
                className="sr-only"
                onChange={handleFileInput}
                disabled={uploading}
              />
            </label>
            <p className="mt-1 text-xs text-gray-500">APK files up to 100MB</p>
          </div>
        </div>
      </div>
    </div>
  );
};

const ScanCard = ({ scan, onViewDetails, onDelete }) => {
  const getSeverityStats = () => {
    if (!scan.findings) return { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    return scan.findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
  };

  const severityStats = getSeverityStats();
  const totalFindings = scan.findings?.length || 0;

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-3">
            <DocumentTextIcon className="h-5 w-5 text-gray-400" />
            <h3 className="text-lg font-medium text-gray-900 truncate">{scan.file_name}</h3>
            <StatusBadge status={scan.scan_status} />
          </div>
          
          {scan.app_info && scan.app_info.package_name !== 'pending' && (
            <div className="mb-3">
              <p className="text-sm text-gray-600">
                <span className="font-medium">Package:</span> {scan.app_info.package_name}
              </p>
              {scan.app_info.version_name && (
                <p className="text-sm text-gray-600">
                  <span className="font-medium">Version:</span> {scan.app_info.version_name}
                </p>
              )}
            </div>
          )}

          {scan.scan_status === 'COMPLETED' && (
            <div className="mb-3">
              <div className="flex items-center gap-4 text-sm">
                <span className="text-gray-600">Findings: <span className="font-medium">{totalFindings}</span></span>
                {severityStats.HIGH > 0 && <span className="text-red-600">HIGH: {severityStats.HIGH}</span>}
                {severityStats.MEDIUM > 0 && <span className="text-yellow-600">MEDIUM: {severityStats.MEDIUM}</span>}
                {severityStats.LOW > 0 && <span className="text-blue-600">LOW: {severityStats.LOW}</span>}
              </div>
            </div>
          )}

          <div className="flex items-center gap-4 text-xs text-gray-500">
            <span>{(scan.file_size / 1024 / 1024).toFixed(2)} MB</span>
            <span>{new Date(scan.scan_time).toLocaleString()}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 ml-4">
          {scan.scan_status === 'COMPLETED' && (
            <button
              onClick={() => onViewDetails(scan)}
              className="p-2 text-gray-400 hover:text-blue-600 transition-colors"
              title="View Details"
            >
              <EyeIcon className="h-4 w-4" />
            </button>
          )}
          <button
            onClick={() => onDelete(scan.id)}
            className="p-2 text-gray-400 hover:text-red-600 transition-colors"
            title="Delete Scan"
          >
            <TrashIcon className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

const ScanDetails = ({ scan, onClose }) => {
  const getSeverityStats = () => {
    if (!scan.findings) return { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    return scan.findings.reduce((acc, finding) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
  };

  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  const severityStats = getSeverityStats();
  const categories = [...new Set(scan.findings?.map(f => f.category) || [])];

  const filteredFindings = scan.findings?.filter(finding => {
    const severityMatch = selectedSeverity === 'ALL' || finding.severity === selectedSeverity;
    const categoryMatch = selectedCategory === 'ALL' || finding.category === selectedCategory;
    return severityMatch && categoryMatch;
  }) || [];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-hidden">
        <div className="flex items-center justify-between p-6 border-b border-gray-200">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">{scan.file_name}</h2>
            <p className="text-sm text-gray-600 mt-1">
              Package: {scan.app_info?.package_name} | Version: {scan.app_info?.version_name || 'N/A'}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 transition-colors"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(90vh-140px)]">
          {/* Summary Stats */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-red-50 p-4 rounded-lg border border-red-200">
              <div className="text-2xl font-bold text-red-600">{severityStats.HIGH}</div>
              <div className="text-sm text-red-600">High Severity</div>
            </div>
            <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
              <div className="text-2xl font-bold text-yellow-600">{severityStats.MEDIUM}</div>
              <div className="text-sm text-yellow-600">Medium Severity</div>
            </div>
            <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
              <div className="text-2xl font-bold text-blue-600">{severityStats.LOW}</div>
              <div className="text-sm text-blue-600">Low Severity</div>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <div className="text-2xl font-bold text-gray-600">{severityStats.INFO}</div>
              <div className="text-sm text-gray-600">Info</div>
            </div>
          </div>

          {/* App Information */}
          {scan.app_info && (
            <div className="bg-gray-50 p-4 rounded-lg mb-6">
              <h3 className="text-lg font-medium text-gray-900 mb-3">Application Information</h3>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p><span className="font-medium">Package Name:</span> {scan.app_info.package_name}</p>
                  <p><span className="font-medium">Version Name:</span> {scan.app_info.version_name || 'N/A'}</p>
                  <p><span className="font-medium">Version Code:</span> {scan.app_info.version_code || 'N/A'}</p>
                </div>
                <div>
                  <p><span className="font-medium">Min SDK:</span> {scan.app_info.min_sdk_version || 'N/A'}</p>
                  <p><span className="font-medium">Target SDK:</span> {scan.app_info.target_sdk_version || 'N/A'}</p>
                  <p><span className="font-medium">Permissions:</span> {scan.app_info.permissions?.length || 0}</p>
                </div>
              </div>
            </div>
          )}

          {/* Filters */}
          <div className="flex gap-4 mb-6">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm"
            >
              <option value="ALL">All Severities</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Info</option>
            </select>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm"
            >
              <option value="ALL">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>

          {/* Findings */}
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-gray-900">
              Findings ({filteredFindings.length})
            </h3>
            {filteredFindings.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                No findings match the selected filters
              </div>
            ) : (
              filteredFindings.map((finding, index) => (
                <div key={index} className="bg-white border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="text-md font-medium text-gray-900">{finding.title}</h4>
                    <div className="flex gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <CategoryBadge category={finding.category} />
                    </div>
                  </div>
                  <p className="text-sm text-gray-600 mb-2">{finding.description}</p>
                  {finding.file_path && (
                    <p className="text-xs text-gray-500 mb-1">
                      <span className="font-medium">File:</span> {finding.file_path}
                      {finding.line_number && ` (Line ${finding.line_number})`}
                    </p>
                  )}
                  {finding.cve_id && (
                    <p className="text-xs text-gray-500 mb-1">
                      <span className="font-medium">CVE:</span> {finding.cve_id}
                    </p>
                  )}
                  {finding.remediation && (
                    <div className="mt-2 p-2 bg-blue-50 rounded text-xs text-blue-800">
                      <span className="font-medium">Remediation:</span> {finding.remediation}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

const Dashboard = ({ stats }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <ChartBarIcon className="h-8 w-8 text-blue-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-500">Total Scans</p>
            <p className="text-2xl font-semibold text-gray-900">{stats.total_scans || 0}</p>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <ShieldCheckIcon className="h-8 w-8 text-green-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-500">Completed</p>
            <p className="text-2xl font-semibold text-gray-900">{stats.completed_scans || 0}</p>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <ClockIcon className="h-8 w-8 text-yellow-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-500">Pending</p>
            <p className="text-2xl font-semibold text-gray-900">{stats.pending_scans || 0}</p>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex items-center">
          <div className="flex-shrink-0">
            <ExclamationTriangleIcon className="h-8 w-8 text-red-600" />
          </div>
          <div className="ml-4">
            <p className="text-sm font-medium text-gray-500">Failed</p>
            <p className="text-2xl font-semibold text-gray-900">{stats.failed_scans || 0}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

function App() {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({});
  const [uploading, setUploading] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API}/scans`);
      setScans(response.data);
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchScans(), fetchStats()]);
      setLoading(false);
    };
    
    loadData();
    
    // Refresh data every 5 seconds
    const interval = setInterval(() => {
      fetchScans();
      fetchStats();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const handleUpload = async (file) => {
    setUploading(true);
    
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post(`${API}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      console.log('Upload successful:', response.data);
      fetchScans();
      fetchStats();
    } catch (error) {
      console.error('Upload failed:', error);
      alert('Upload failed: ' + (error.response?.data?.detail || error.message));
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteScan = async (scanId) => {
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    
    try {
      await axios.delete(`${API}/scans/${scanId}`);
      fetchScans();
      fetchStats();
    } catch (error) {
      console.error('Delete failed:', error);
      alert('Delete failed: ' + (error.response?.data?.detail || error.message));
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <ShieldCheckIcon className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900">Android Vulnerability Scanner</h1>
          </div>
          <p className="text-gray-600">
            Advanced static analysis platform for detecting vulnerabilities in Android applications
          </p>
        </div>

        {/* Dashboard Stats */}
        <Dashboard stats={stats} />

        {/* Upload Section */}
        <UploadSection onUpload={handleUpload} uploading={uploading} />

        {/* Scans List */}
        <div>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-gray-900">Scan Results</h2>
            <span className="text-sm text-gray-500">{scans.length} total scans</span>
          </div>

          {scans.length === 0 ? (
            <div className="text-center py-12">
              <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400" />
              <h3 className="mt-2 text-sm font-medium text-gray-900">No scans yet</h3>
              <p className="mt-1 text-sm text-gray-500">
                Upload an APK file to start analyzing for vulnerabilities.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {scans.map((scan) => (
                <ScanCard
                  key={scan.id}
                  scan={scan}
                  onViewDetails={setSelectedScan}
                  onDelete={handleDeleteScan}
                />
              ))}
            </div>
          )}
        </div>

        {/* Scan Details Modal */}
        {selectedScan && (
          <ScanDetails
            scan={selectedScan}
            onClose={() => setSelectedScan(null)}
          />
        )}
      </div>
    </div>
  );
}

export default App;