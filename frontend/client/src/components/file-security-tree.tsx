import {
    AlertTriangle,
    ChevronDown,
    ChevronRight,
    FileText,
    Folder,
    FolderOpen,
    Search,
    Shield,
} from "lucide-react"
import { useState } from "react"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible"
import { Input } from "./ui/input"

interface FileNode {
  id: string
  name: string
  type: "file" | "folder"
  path: string
  vulnerabilities?: number
  severity?: "critical" | "high" | "medium" | "low"
  children?: FileNode[]
}

const fileTree: FileNode[] = [
  {
    id: "1",
    name: "src",
    type: "folder",
    path: "/src",
    children: [
      {
        id: "2",
        name: "auth",
        type: "folder",
        path: "/src/auth",
        children: [
          {
            id: "3",
            name: "login.js",
            type: "file",
            path: "/src/auth/login.js",
            vulnerabilities: 2,
            severity: "critical",
          },
          {
            id: "4",
            name: "register.js",
            type: "file",
            path: "/src/auth/register.js",
            vulnerabilities: 1,
            severity: "medium",
          },
        ],
      },
      {
        id: "5",
        name: "api",
        type: "folder",
        path: "/src/api",
        children: [
          {
            id: "6",
            name: "users.js",
            type: "file",
            path: "/src/api/users.js",
            vulnerabilities: 3,
            severity: "high",
          },
          {
            id: "7",
            name: "payments.js",
            type: "file",
            path: "/src/api/payments.js",
            vulnerabilities: 1,
            severity: "low",
          },
        ],
      },
      {
        id: "8",
        name: "utils",
        type: "folder",
        path: "/src/utils",
        children: [
          {
            id: "9",
            name: "sanitize.js",
            type: "file",
            path: "/src/utils/sanitize.js",
            vulnerabilities: 2,
            severity: "high",
          },
          {
            id: "10",
            name: "helpers.js",
            type: "file",
            path: "/src/utils/helpers.js",
          },
        ],
      },
    ],
  },
  {
    id: "11",
    name: "config",
    type: "folder",
    path: "/config",
    children: [
      {
        id: "12",
        name: "database.js",
        type: "file",
        path: "/config/database.js",
        vulnerabilities: 1,
        severity: "medium",
      },
      {
        id: "13",
        name: "auth.js",
        type: "file",
        path: "/config/auth.js",
        vulnerabilities: 1,
        severity: "low",
      },
    ],
  },
]

const getSeverityColor = (severity?: string) => {
  switch (severity) {
    case "critical": return "text-red-500"
    case "high": return "text-orange-500"
    case "medium": return "text-yellow-500"
    case "low": return "text-green-500"
    default: return "text-gray-500"
  }
}

const getSeverityBadgeVariant = (severity?: string) => {
  switch (severity) {
    case "critical": return "destructive" as const
    case "high": return "destructive" as const
    case "medium": return "default" as const
    case "low": return "secondary" as const
    default: return "outline" as const
  }
}

function FileNodeComponent({ node, level, searchTerm }: { node: FileNode; level: number; searchTerm: string }) {
  const [isOpen, setIsOpen] = useState(level < 2)
  const shouldShow = searchTerm === "" || node.name.toLowerCase().includes(searchTerm.toLowerCase()) || node.path.toLowerCase().includes(searchTerm.toLowerCase())
  const hasVulnerabilities = node.vulnerabilities && node.vulnerabilities > 0

  if (!shouldShow) return null

  if (node.type === "file") {
    return (
      <div className="flex items-center gap-2 py-1 px-2 rounded hover-elevate cursor-pointer" style={{ marginLeft: `${level * 16}px` }}>
        <FileText className="h-5 w-5 text-muted-foreground flex-shrink-0" />
        <span className="text-sm font-mono flex-1">{node.name}</span>
        {hasVulnerabilities && (
          <>
            <Badge variant={getSeverityBadgeVariant(node.severity)} className="text-xs">{node.vulnerabilities}</Badge>
            <AlertTriangle className={`h-4 w-4 ${getSeverityColor(node.severity)} flex-shrink-0`} />
          </>
        )}
      </div>
    )
  }

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger asChild>
        <div className="flex items-center gap-2 py-1 px-2 rounded hover-elevate cursor-pointer" style={{ marginLeft: `${level * 16}px` }}>
          {isOpen ? (<><ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" /><FolderOpen className="h-5 w-5 text-primary flex-shrink-0" /></>) : (<><ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" /><Folder className="h-5 w-5 text-primary flex-shrink-0" /></>)}
          <span className="text-sm font-mono flex-1">{node.name}</span>
          {node.children && (<span className="text-xs text-muted-foreground">{node.children.filter((child: any) => child.vulnerabilities).length > 0 && (<Shield className="h-4 w-4 text-orange-500" />)}</span>)}
        </div>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {node.children?.map((child) => (<FileNodeComponent key={child.id} node={child} level={level + 1} searchTerm={searchTerm} />))}
      </CollapsibleContent>
    </Collapsible>
  )
}

export function FileSecurityTree() {
  const [searchTerm, setSearchTerm] = useState("")
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2"><Folder className="h-5 w-5 text-primary" />File Security Overview</CardTitle>
          <div className="flex gap-2">
            <Button variant="outline" size="sm">Expand All</Button>
            <Button variant="outline" size="sm">Collapse All</Button>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search files and folders..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="pl-10" />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="flex flex-col h-[400px]">
          <div className="flex-1 overflow-y-auto px-4">
            {fileTree.map((node) => (
              <FileNodeComponent key={node.id} node={node} level={0} searchTerm={searchTerm} />
            ))}
          </div>
          <div className="mt-4 pt-4 px-4 border-t border-gray-800 bg-gradient-to-b from-gray-900/50 to-gray-900">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  <span>Critical: 2</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                  <span>High: 3</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                  <span>Medium: 2</span>
                </div>
                <div className="flex items-center gap-1">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span>Low: 2</span>
                </div>
              </div>
              <Button variant="outline" size="sm">Rescan Files</Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
