// 1

// import {
//     Bell,
//     Download,
//     Filter,
//     Plus,
//     RefreshCw,
//     Search,
//     Settings,
// } from "lucide-react"
// import React, { useState } from "react"
// import { FileSecurityTree } from "../components/file-security-tree"
// import { RepositoryScanStatus } from "../components/repository-scan-status"
// import { SecurityAnalyticsChart, SeverityDistributionChart } from "../components/security-analytics-chart"

// import { SecurityOverviewCards } from "../components/security-overview-cards"
// import { Badge } from "../components/ui/badge"
// import { Button } from "../components/ui/button"
// import { Card, CardContent } from "../components/ui/card"
// import { Input } from "../components/ui/input"
// import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select"

// export default function Dashboard(): JSX.Element {
// 	const [searchQuery, setSearchQuery] = useState("")
// 	const [filterBy, setFilterBy] = useState("all")
// 	const [isRefreshing, setIsRefreshing] = useState(false)

// 	const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
// 		e.preventDefault()
// 		console.log(`Searching for: ${searchQuery}`)
// 	}

// 	const handleRefresh = () => {
// 		setIsRefreshing(true)
// 		console.log('Refreshing dashboard data')
// 		setTimeout(() => setIsRefreshing(false), 2000)
// 	}

// 	const handleAddRepository = () => {
// 		console.log('Adding new repository')
// 	}

// 	const handleExportReport = () => {
// 		console.log('Exporting security report')
// 	}

// 	const handleViewNotifications = () => {
// 		console.log('Viewing notifications')
// 	}

// 	const handleOpenSettings = () => {
// 		console.log('Opening settings')
// 	}

// 	return (
// 		<div className="space-y-6 p-4 sm:p-6 lg:p-8">
// 			{/* Dashboard Header */}
// 			<div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
// 				<div>
// 					<h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-500 via-purple-500 to-blue-700 bg-clip-text text-transparent">
// 						Advanced Security Operations Center
// 					</h1>
// 					<p className="text-muted-foreground mt-1">
// 						Real-time vulnerability detection and security monitoring across enterprise repositories
// 					</p>
// 				</div>
// 				<div className="flex gap-2">
// 					<Button
// 						variant="outline"
// 						size="sm"
// 						onClick={handleViewNotifications}
// 						data-testid="button-notifications"
// 						className="bg-background/70 backdrop-blur-sm"
// 					>
// 						<Bell className="h-4 w-4 mr-2" />
// 						Alerts
// 						<Badge variant="destructive" className="ml-2">
// 							3
// 						</Badge>
// 					</Button>
// 					<Button
// 						variant="outline"
// 						size="sm"
// 						onClick={handleOpenSettings}
// 						data-testid="button-settings"
// 						className="bg-background/70 backdrop-blur-sm"
// 					>
// 						<Settings className="h-4 w-4 mr-2" />
// 						Settings
// 					</Button>
// 				</div>
// 			</div>

// 			{/* Action Bar */}
// 			<Card className="bg-background/70 backdrop-blur-sm border-gray-800">
// 				<CardContent className="p-4">
// 					<div className="flex flex-wrap items-center gap-4">
// 						<form onSubmit={handleSearch} className="flex-1 min-w-[250px]">
// 							<div className="relative">
// 								<Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
// 								<Input
// 									placeholder="Search repositories, vulnerabilities, or files..."
// 									value={searchQuery}
// 									onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
// 									className="pl-10 bg-background/50"
// 									data-testid="input-dashboard-search"
// 								/>
// 							</div>
// 						</form>
            
// 						<Select value={filterBy} onValueChange={setFilterBy}>
// 							<SelectTrigger className="w-full sm:w-48" data-testid="select-filter">
// 								<Filter className="h-4 w-4 mr-2" />
// 								<SelectValue placeholder="Filter by" />
// 							</SelectTrigger>
// 							<SelectContent>
// 								<SelectItem value="all">All Items</SelectItem>
// 								<SelectItem value="critical">Critical Only</SelectItem>
// 								<SelectItem value="repositories">Repositories</SelectItem>
// 								<SelectItem value="vulnerabilities">Vulnerabilities</SelectItem>
// 								<SelectItem value="recent">Recent Activity</SelectItem>
// 							</SelectContent>
// 						</Select>
            
// 						<div className="flex gap-2 flex-wrap">
// 							<Button
// 								variant="outline"
// 								size="sm"
// 								onClick={handleRefresh}
// 								disabled={isRefreshing}
// 								data-testid="button-refresh-dashboard"
// 							>
// 								<RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
// 								Refresh
// 							</Button>
            
// 							<Button
// 								variant="outline"
// 								size="sm"
// 								onClick={handleExportReport}
// 								data-testid="button-export-report"
// 							>
// 								<Download className="h-4 w-4 mr-2" />
// 								Export
// 							</Button>
            
// 							<Button
// 								size="sm"
// 								onClick={handleAddRepository}
// 								data-testid="button-add-repository"
// 								className="bg-blue-600 hover:bg-blue-700 text-white"
// 							>
// 								<Plus className="h-4 w-4 mr-2" />
// 								Add Repository
// 							</Button>
// 						</div>
// 					</div>
// 				</CardContent>
// 			</Card>

// 			{/* Main Dashboard Content */}
// 			<div className="grid gap-6">
// 				{/* Security Overview Cards */}
// 				<div className="w-full">
// 					<SecurityOverviewCards />
// 				</div>

// 				{/* Security Analytics Charts - Full Width Bar Graph */}
// 				<div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl p-4 shadow-lg backdrop-blur-sm">
// 					<SecurityAnalyticsChart />
// 				</div>

// 				{/* Severity Distribution and File Security Grid */}
// 				<div className="grid gap-6 lg:grid-cols-2">
// 					{/* Severity Distribution */}
// 					<div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
// 						<SeverityDistributionChart />
// 					</div>
					
// 					{/* File Security Overview */}
// 					<div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
// 						<FileSecurityTree />
// 					</div>
// 				</div>

// 				{/* Repository Scan Status */}
// 				<div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
// 					<RepositoryScanStatus />
// 				</div>
// 			</div>
// 		</div>
// 	)
// }






// 2 
// import {
// 	Bell,
// 	Download,
// 	Filter,
// 	Plus,
// 	RefreshCw,
// 	Search,
// 	Settings,
// } from "lucide-react"
// import React, { useState } from "react"
// import { FileSecurityTree } from "../components/file-security-tree"
// import { RepositoryScanStatus } from "../components/repository-scan-status"
// import { SecurityAnalyticsChart, SeverityDistributionChart } from "../components/security-analytics-chart"

// import { SecurityOverviewCards } from "../components/security-overview-cards"
// import { Badge } from "../components/ui/badge"
// import { Button } from "../components/ui/button"
// import { Card, CardContent } from "../components/ui/card"
// import { Input } from "../components/ui/input"
// import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select"

// export default function Dashboard(): JSX.Element {
//     const [searchQuery, setSearchQuery] = useState("")
//     const [filterBy, setFilterBy] = useState("all")
//     const [isRefreshing, setIsRefreshing] = useState(false)

//     const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
//         e.preventDefault()
//         console.log(`Searching for: ${searchQuery}`)
//     }

//     const handleRefresh = () => {
//         setIsRefreshing(true)
//         console.log("Refreshing dashboard data")
//         setTimeout(() => setIsRefreshing(false), 2000)
//     }

//     const handleAddRepository = () => {
//         console.log("Adding new repository")
//     }

//     const handleExportReport = () => {
//         console.log("Exporting security report")
//     }

//     const handleViewNotifications = () => {
//         console.log("Viewing notifications")
//     }

//     const handleOpenSettings = () => {
//         console.log("Opening settings")
//     }

//     return (
//         <div className="w-full h-full min-h-screen space-y-6 px-4 sm:px-6 lg:px-8 py-6">
//             {/* Dashboard Header */}
//             <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 w-full">
//                 <div>
//                     <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-500 via-purple-500 to-blue-700 bg-clip-text text-transparent">
//                         Advanced Security Operations Center
//                     </h1>
//                     <p className="text-muted-foreground mt-1">
//                         Real-time vulnerability detection and security monitoring across enterprise repositories
//                     </p>
//                 </div>
//                 <div className="flex gap-2 flex-wrap">
//                     <Button
//                         variant="outline"
//                         size="sm"
//                         onClick={handleViewNotifications}
//                         data-testid="button-notifications"
//                         className="bg-background/70 backdrop-blur-sm"
//                     >
//                         <Bell className="h-4 w-4 mr-2" />
//                         Alerts
//                         <Badge variant="destructive" className="ml-2">
//                             3
//                         </Badge>
//                     </Button>
//                     <Button
//                         variant="outline"
//                         size="sm"
//                         onClick={handleOpenSettings}
//                         data-testid="button-settings"
//                         className="bg-background/70 backdrop-blur-sm"
//                     >
//                         <Settings className="h-4 w-4 mr-2" />
//                         Settings
//                     </Button>
//                 </div>
//             </div>

//             {/* Action Bar */}
//             <Card className="bg-background/70 backdrop-blur-sm border-gray-800 w-full">
//                 <CardContent className="p-4">
//                     <div className="flex flex-wrap items-center gap-4">
//                         <form onSubmit={handleSearch} className="flex-1 min-w-[250px]">
//                             <div className="relative">
//                                 <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
//                                 <Input
//                                     placeholder="Search repositories, vulnerabilities, or files..."
//                                     value={searchQuery}
//                                     onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
//                                     className="pl-10 bg-background/50 w-full"
//                                     data-testid="input-dashboard-search"
//                                 />
//                             </div>
//                         </form>

//                         <Select value={filterBy} onValueChange={setFilterBy}>
//                             <SelectTrigger className="w-full sm:w-48" data-testid="select-filter">
//                                 <Filter className="h-4 w-4 mr-2" />
//                                 <SelectValue placeholder="Filter by" />
//                             </SelectTrigger>
//                             <SelectContent>
//                                 <SelectItem value="all">All Items</SelectItem>
//                                 <SelectItem value="critical">Critical Only</SelectItem>
//                                 <SelectItem value="repositories">Repositories</SelectItem>
//                                 <SelectItem value="vulnerabilities">Vulnerabilities</SelectItem>
//                                 <SelectItem value="recent">Recent Activity</SelectItem>
//                             </SelectContent>
//                         </Select>

//                         <div className="flex gap-2 flex-wrap">
//                             <Button
//                                 variant="outline"
//                                 size="sm"
//                                 onClick={handleRefresh}
//                                 disabled={isRefreshing}
//                                 data-testid="button-refresh-dashboard"
//                             >
//                                 <RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? "animate-spin" : ""}`} />
//                                 Refresh
//                             </Button>

//                             <Button
//                                 variant="outline"
//                                 size="sm"
//                                 onClick={handleExportReport}
//                                 data-testid="button-export-report"
//                             >
//                                 <Download className="h-4 w-4 mr-2" />
//                                 Export
//                             </Button>

//                             <Button
//                                 size="sm"
//                                 onClick={handleAddRepository}
//                                 data-testid="button-add-repository"
//                                 className="bg-blue-600 hover:bg-blue-700 text-white"
//                             >
//                                 <Plus className="h-4 w-4 mr-2" />
//                                 Add Repository
//                             </Button>
//                         </div>
//                     </div>
//                 </CardContent>
//             </Card>

//             {/* Main Dashboard Content */}
//             <div className="grid gap-6 w-full">
//                 {/* Security Overview Cards */}
//                 <div className="w-full">
//                     <SecurityOverviewCards />
//                 </div>

//                 {/* Security Analytics Charts */}
//                 <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl p-4 shadow-lg backdrop-blur-sm">
//                     <SecurityAnalyticsChart />
//                 </div>

//                 {/* Severity Distribution and File Security Grid */}
//                 <div className="grid gap-6 w-full lg:grid-cols-2">
//                     <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
//                         <SeverityDistributionChart />
//                     </div>
//                     <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
//                         <FileSecurityTree />
//                     </div>
//                 </div>

//                 {/* Repository Scan Status */}
//                 <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm">
//                     <RepositoryScanStatus />
//                 </div>
//             </div>
//         </div>
//     )
// }




// 3

import {
  Bell,
  Download,
  Filter,
  Plus,
  RefreshCw,
  Search,
  Settings,
} from "lucide-react";
import React, { useState } from "react";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent } from "../components/ui/card";
import { Input } from "../components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../components/ui/select";

export default function Dashboard(): JSX.Element {
  // Search and filter states
  const [searchQuery, setSearchQuery] = useState("");
  const [filterBy, setFilterBy] = useState("all");
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Dynamic data states
  const [alertCount, setAlertCount] = useState(3);
  const [totalRepositories, setTotalRepositories] = useState(12);
  const [criticalVulnerabilities, setCriticalVulnerabilities] = useState(5);
  const [recentAlerts, setRecentAlerts] = useState(2);
  const [filesScanned, setFilesScanned] = useState(124);

  const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    console.log(`Searching for: ${searchQuery}`);
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    console.log("Refreshing dashboard data");
    setTimeout(() => {
      setAlertCount(alertCount + 1);
      setRecentAlerts(recentAlerts + 1);
      setIsRefreshing(false);
    }, 2000);
  };

  const handleAddRepository = () => {
    console.log("Adding new repository");
    setTotalRepositories(totalRepositories + 1);
  };

  const handleExportReport = () => console.log("Exporting security report");
  const handleViewNotifications = () => console.log("Viewing notifications");
  const handleOpenSettings = () => console.log("Opening settings");

  return (
    <div className="min-h-screen bg-gray-950 w-full overflow-x-hidden">
      <main className="flex flex-col px-4 sm:px-6 py-8 w-full max-w-full">
        {/* ---------------------- Dashboard Header ---------------------- */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 w-full">
          <div className="min-w-0">
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-500 via-purple-500 to-blue-700 bg-clip-text text-transparent">
              Advanced Security Operations Center
            </h1>
            <p className="text-muted-foreground mt-1 truncate">
              Real-time vulnerability detection and security monitoring across
              enterprise repositories
            </p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={handleViewNotifications}
              data-testid="button-notifications"
              className="bg-background/70 backdrop-blur-sm"
            >
              <Bell className="h-4 w-4 mr-2" />
              Alerts
              <Badge variant="destructive" className="ml-2">
                {alertCount}
              </Badge>
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleOpenSettings}
              data-testid="button-settings"
              className="bg-background/70 backdrop-blur-sm"
            >
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
          </div>
        </div>

        {/* ---------------------- Action Bar ---------------------- */}
        <Card className="bg-background/70 backdrop-blur-sm border-gray-800 w-full mt-6">
          <CardContent className="p-4">
            <div className="flex flex-wrap items-center gap-4 w-full">
              <form onSubmit={handleSearch} className="flex-1 min-w-0">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search repositories, vulnerabilities, or files..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10 bg-background/50 w-full"
                    data-testid="input-dashboard-search"
                  />
                </div>
              </form>

              <Select value={filterBy} onValueChange={setFilterBy}>
                <SelectTrigger
                  className="w-full sm:w-48"
                  data-testid="select-filter"
                >
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Filter by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Items</SelectItem>
                  <SelectItem value="critical">Critical Only</SelectItem>
                  <SelectItem value="repositories">Repositories</SelectItem>
                  <SelectItem value="vulnerabilities">Vulnerabilities</SelectItem>
                  <SelectItem value="recent">Recent Activity</SelectItem>
                </SelectContent>
              </Select>

              <div className="flex gap-2 flex-wrap">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleRefresh}
                  disabled={isRefreshing}
                  data-testid="button-refresh-dashboard"
                >
                  <RefreshCw
                    className={`h-4 w-4 mr-2 ${
                      isRefreshing ? "animate-spin" : ""
                    }`}
                  />
                  Refresh
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleExportReport}
                  data-testid="button-export-report"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Export
                </Button>

                <Button
                  size="sm"
                  onClick={handleAddRepository}
                  data-testid="button-add-repository"
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Add Repository
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* ---------------------- Main Dashboard Content ---------------------- */}
        <div className="grid gap-6 mt-6 w-full">
          {/* Stats cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 w-full">
            <div className="p-4 bg-gray-800 rounded-lg shadow-md w-full">
              <h2 className="text-sm font-medium text-muted-foreground">
                Total Repositories
              </h2>
              <p className="text-2xl font-bold">{totalRepositories}</p>
            </div>
            <div className="p-4 bg-gray-800 rounded-lg shadow-md w-full">
              <h2 className="text-sm font-medium text-muted-foreground">
                Critical Vulnerabilities
              </h2>
              <p className="text-2xl font-bold">{criticalVulnerabilities}</p>
            </div>
            <div className="p-4 bg-gray-800 rounded-lg shadow-md w-full">
              <h2 className="text-sm font-medium text-muted-foreground">
                Recent Alerts
              </h2>
              <p className="text-2xl font-bold">{recentAlerts}</p>
            </div>
            <div className="p-4 bg-gray-800 rounded-lg shadow-md w-full">
              <h2 className="text-sm font-medium text-muted-foreground">
                Files Scanned
              </h2>
              <p className="text-2xl font-bold">{filesScanned}</p>
            </div>
          </div>

          {/* Vulnerability Trends */}
          <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl p-4 shadow-lg backdrop-blur-sm">
            <h3 className="text-lg font-semibold mb-2">Vulnerability Trends</h3>
            <div className="h-64 flex items-center justify-center text-muted-foreground">
              Security Analytics Chart Placeholder
            </div>
          </div>

          {/* Charts */}
          <div className="grid gap-6 w-full md:grid-cols-2">
            <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm p-4">
              <h3 className="text-lg font-semibold mb-2">
                Severity Distribution
              </h3>
              <div className="h-64 flex items-center justify-center text-muted-foreground">
                Severity Distribution Chart Placeholder
              </div>
            </div>
            <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm p-4">
              <h3 className="text-lg font-semibold mb-2">File Security Tree</h3>
              <div className="h-64 flex items-center justify-center text-muted-foreground">
                File Security Tree Placeholder
              </div>
            </div>
          </div>

          {/* Repository Status */}
          <div className="w-full bg-gradient-to-b from-gray-900/60 to-gray-950/80 border border-gray-800 rounded-xl shadow-lg backdrop-blur-sm p-4">
            <h3 className="text-lg font-semibold mb-2">
              Repository Scan Status
            </h3>
            <div className="h-32 flex items-center justify-center text-muted-foreground">
              Repository Scan Status Placeholder
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}