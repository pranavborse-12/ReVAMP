import { useSearchParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { AlertTriangle, Clock, FileText, Loader, ChevronUp, ChevronDown } from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Separator } from "../components/ui/separator";

const API_BASE_URL = "http://localhost:8000";

interface ScanResult {
  scan_id: string;
  repo_owner: string;
  repo_name: string;
  status: string;
  total_issues: number;
  severity_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    warning: number;
  };
  vulnerabilities: Array<{
    scanner: string;
    rule_id: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "WARNING";
    message: string;
    vulnerability_type: string;
    location: {
      file: string;
      start_line: number;
      end_line: number;
    };
    code_snippet?: string;
    cwe?: string[];
    owasp?: string[];
  }>;
  scan_duration?: number;
  completed_at?: string;
  scanner_used?: string;
  detected_languages?: string[];
}

const getSeverityColor = (severity: string) => {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "text-red-500 bg-red-500/10";
    case "HIGH": return "text-orange-500 bg-orange-500/10";
    case "MEDIUM": return "text-yellow-500 bg-yellow-500/10";
    case "LOW": return "text-green-500 bg-green-500/10";
    default: return "text-gray-500 bg-gray-500/10";
  }
};

const getSeverityBadgeColor = (severity: string) => {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "destructive";
    case "HIGH": return "destructive";
    case "MEDIUM": return "default";
    case "LOW": return "secondary";
    default: return "outline";
  }
};

export default function Vulnerabilities() {
  const [searchParams] = useSearchParams();
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);
  const [pollCount, setPollCount] = useState(0);

  const scanId = searchParams.get("scan_id");

  useEffect(() => {
    if (!scanId) {
      setError("No scan ID provided");
      setLoading(false);
      return;
    }

    const fetchScanResult = async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/scanning/scans/${scanId}`,
          { credentials: "include" }
        );

        if (!res.ok) {
          throw new Error("Failed to fetch scan results");
        }

        const data = await res.json();
        setScanResult(data);
        setLoading(false);
        setPollCount(0);

        // If still scanning, continue polling
        if (data.status && data.status !== "completed" && data.status !== "failed") {
          setPollCount(prev => prev + 1);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Error fetching scan results");
        setLoading(false);
      }
    };

    fetchScanResult();

    // Poll every 2 seconds if scan is still in progress
    let pollInterval: NodeJS.Timeout | null = null;
    if (scanId) {
      pollInterval = setInterval(() => {
        fetchScanResult();
      }, 2000);
    }

    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [scanId]);

  if (loading && !scanResult) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <Loader className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-500" />
          <p className="text-zinc-400">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error || !scanResult) {
    return (
      <div className="p-4">
        <Card className="border-red-500/20 bg-red-500/5">
          <CardContent className="pt-6">
            <p className="text-red-400">{error || "No scan results available"}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isScanning = scanResult.status && !["completed", "failed"].includes(scanResult.status);

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-2xl">
                {scanResult.repo_owner}/{scanResult.repo_name}
              </CardTitle>
              <p className="text-sm text-zinc-400 mt-2">
                Scan ID: {scanResult.scan_id}
              </p>
            </div>
            {isScanning && (
              <div className="flex items-center gap-2 px-3 py-1 bg-blue-500/10 text-blue-400 rounded-lg text-sm">
                <Loader className="h-4 w-4 animate-spin" />
                Scanning...
              </div>
            )}
            {scanResult.status === "completed" && (
              <div className="flex items-center gap-2 px-3 py-1 bg-green-500/10 text-green-400 rounded-lg text-sm">
                ✓ Completed
              </div>
            )}
            {scanResult.status === "failed" && (
              <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 text-red-400 rounded-lg text-sm">
                ✗ Failed
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-sm">
            <div>
              <p className="text-zinc-400">Total Issues</p>
              <p className="text-2xl font-bold">{scanResult.total_issues}</p>
            </div>
            <div>
              <p className="text-zinc-400">Critical</p>
              <p className="text-2xl font-bold text-red-500">{scanResult.severity_summary.critical}</p>
            </div>
            <div>
              <p className="text-zinc-400">High</p>
              <p className="text-2xl font-bold text-orange-500">{scanResult.severity_summary.high}</p>
            </div>
            <div>
              <p className="text-zinc-400">Medium</p>
              <p className="text-2xl font-bold text-yellow-500">{scanResult.severity_summary.medium}</p>
            </div>
            <div>
              <p className="text-zinc-400">Low</p>
              <p className="text-2xl font-bold text-green-500">{scanResult.severity_summary.low}</p>
            </div>
            <div>
              <p className="text-zinc-400">Duration</p>
              <p className="text-xl font-bold">{scanResult.scan_duration?.toFixed(2)}s</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            Detected Vulnerabilities ({scanResult.vulnerabilities?.length || 0})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {!scanResult.vulnerabilities || scanResult.vulnerabilities.length === 0 ? (
            <p className="text-zinc-400 text-center py-8">✓ No vulnerabilities detected!</p>
          ) : (
            scanResult.vulnerabilities.map((vuln, idx) => (
              <div key={idx}>
                <button
                  onClick={() => setExpandedVuln(expandedVuln === idx ? null : idx)}
                  className="w-full text-left p-3 rounded-lg hover:bg-zinc-900/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1">
                      <AlertTriangle className={`h-5 w-5 ${getSeverityColor(vuln.severity)}`} />
                      <div className="flex-1">
                        <h4 className="font-medium">{vuln.message}</h4>
                        <p className="text-sm text-zinc-400">{vuln.vulnerability_type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Badge variant={getSeverityBadgeColor(vuln.severity) as any}>
                        {vuln.severity}
                      </Badge>
                      {expandedVuln === idx ? (
                        <ChevronUp className="h-4 w-4 text-zinc-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-zinc-400" />
                      )}
                    </div>
                  </div>
                </button>

                {expandedVuln === idx && (
                  <div className="px-3 py-3 bg-zinc-900/30 rounded-b-lg space-y-3 border-t border-zinc-800">
                    <div className="flex items-center gap-2 text-sm text-zinc-400">
                      <FileText className="h-4 w-4" />
                      <span className="font-mono">{vuln.location.file}:{vuln.location.start_line}</span>
                    </div>
                    <div>
                      <p className="text-xs text-zinc-500 mb-2">Rule ID</p>
                      <p className="text-sm font-mono">{vuln.rule_id}</p>
                    </div>
                    {vuln.scanner && (
                      <div>
                        <p className="text-xs text-zinc-500 mb-2">Scanner</p>
                        <p className="text-sm">{vuln.scanner}</p>
                      </div>
                    )}
                    {vuln.cwe && vuln.cwe.length > 0 && (
                      <div>
                        <p className="text-xs text-zinc-500 mb-2">CWE</p>
                        <div className="flex gap-2 flex-wrap">
                          {vuln.cwe.map((c, i) => (
                            <Badge key={i} variant="outline" className="text-xs">{c}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    {vuln.code_snippet && (
                      <div>
                        <p className="text-xs text-zinc-500 mb-2">Code</p>
                        <pre className="text-xs bg-zinc-950 p-2 rounded overflow-auto max-h-32 text-zinc-300">
                          {vuln.code_snippet}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {idx < (scanResult.vulnerabilities?.length || 0) - 1 && (
                  <Separator className="mt-2" />
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {isScanning && (
        <div className="text-center text-sm text-zinc-400">
          <Loader className="h-4 w-4 animate-spin inline-block mr-2" />
          Scan in progress... (Poll #{pollCount})
        </div>
      )}
    </div>
  );
}