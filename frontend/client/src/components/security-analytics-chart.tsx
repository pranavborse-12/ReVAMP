import { Activity, BarChart3, Download } from "lucide-react"
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"

const vulnerabilityTrends = [ { month: "Sep", critical: 5, high: 17, medium: 32, low: 26, total: 80 } ]
const severityDistribution = [ { name: "Critical", value: 5, color: "#b91c1c", percentage: "6.3%" }, { name: "High", value: 17, color: "#ff4b33", percentage: "21.3%" }, { name: "Medium", value: 32, color: "#fcb001", percentage: "40.0%" }, { name: "Low", value: 26, color: "#29ac5b", percentage: "32.5%" } ]

const CustomTooltip = ({ active, payload, label }: any) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    if (data.total === null) {
      return (<div className="bg-gray-900/95 border border-gray-700 rounded-lg p-3 shadow-xl backdrop-blur-sm"><p className="text-sm font-medium text-gray-200">{label}</p><p className="text-xs text-gray-400 mt-1">No data available - month not reached</p></div>);
    }
    return (<div className="bg-gray-900/95 border border-gray-700 rounded-lg p-3 shadow-xl backdrop-blur-sm min-w-[160px]"><p className="text-sm font-semibold text-gray-100 mb-2">{label}</p><div className="space-y-1">{payload.map((entry: any, index: number) => (<div key={index} className="flex items-center justify-between text-xs"><div className="flex items-center gap-2"><div className="w-2 h-2 rounded-sm" style={{ backgroundColor: entry.color }} /><span className="text-gray-300 capitalize">{entry.dataKey}</span></div><span className="font-mono text-gray-100">{entry.value}</span></div>))}<div className="pt-1 mt-2 border-t border-gray-700"><div className="flex items-center justify-between text-xs font-medium"><span className="text-gray-100">Total</span><span className="font-mono text-gray-100">{data.total}</span></div></div></div></div>);
  }
  return null;
};

export function SecurityAnalyticsChart() {
  const handleExportReport = () => { console.log('Exporting security analytics report') }
  const handleViewDetails = (chartType: string) => { console.log(`Viewing details for: ${chartType}`) }
  return (
    <div className="space-y-6">
      <Card className="border border-gray-700/50 shadow-xl bg-gradient-to-br from-gray-900/90 to-gray-800/40 backdrop-blur-sm">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3"><div className="p-2 rounded-lg bg-blue-500/20 border border-blue-500/30"><Activity className="h-5 w-5 text-blue-400" /></div><div><CardTitle className="text-lg font-semibold text-gray-100">Vulnerability Trends</CardTitle><p className="text-sm text-gray-400 mt-1">12-month projection starting September</p></div></div>
            <div className="flex gap-2"><Button variant="outline" size="sm" onClick={() => handleViewDetails('trends')} className="h-8 text-xs border-gray-600 text-gray-300 hover:bg-gray-700">View Details</Button><Button variant="ghost" size="sm" onClick={handleExportReport} className="h-8 w-8 p-0 text-gray-300 hover:bg-gray-700"><Download className="h-3.5 w-3.5" /></Button></div>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <ResponsiveContainer width="100%" height={400}>
            <BarChart 
              data={vulnerabilityTrends} 
              margin={{ top: 20, right: 30, left: 10, bottom: 20 }} 
              barCategoryGap="20%"
            >
              <CartesianGrid 
                strokeDasharray="3 3" 
                stroke="#374151" 
                strokeOpacity={0.4} 
                vertical={false} 
              />
              <XAxis 
                dataKey="month" 
                axisLine={false} 
                tickLine={false} 
                className="fill-gray-400 text-sm" 
                fontSize={12} 
                fontWeight={500}
                padding={{ left: 20, right: 20 }}
              />
              <YAxis 
                axisLine={false} 
                tickLine={false} 
                className="fill-gray-400 text-xs" 
                fontSize={11} 
                width={45}
                padding={{ top: 20, bottom: 20 }}
              />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine 
                x="Sep" 
                stroke="#3b82f6" 
                strokeDasharray="2 2" 
                strokeOpacity={0.8} 
              />
              <Bar 
                dataKey="critical" 
                stackId="a" 
                fill="#b91c1c" 
                name="Critical" 
                radius={[0, 0, 0, 0]} 
                stroke="rgba(255,255,255,0.1)" 
                strokeWidth={0.5} 
              />
              <Bar 
                dataKey="high" 
                stackId="a" 
                fill="#ff4b33" 
                name="High" 
                radius={[0, 0, 0, 0]} 
                stroke="rgba(255,255,255,0.1)" 
                strokeWidth={0.5} 
              />
              <Bar 
                dataKey="medium" 
                stackId="a" 
                fill="#fcb001" 
                name="Medium" 
                radius={[0, 0, 0, 0]} 
                stroke="rgba(255,255,255,0.1)" 
                strokeWidth={0.5} 
              />
              <Bar 
                dataKey="low" 
                stackId="a" 
                fill="#29ac5b" 
                name="Low" 
                radius={[1, 1, 0, 0]} 
                stroke="rgba(255,255,255,0.1)" 
                strokeWidth={0.5} 
              />
            </BarChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-6 mt-4 pt-4 border-t border-gray-700">{[{ name: 'Critical', color: '#b91c1c' },{ name: 'High', color: '#ff4b33' },{ name: 'Medium', color: '#fcb001' },{ name: 'Low', color: '#29ac5b' }].map((item) => (<div key={item.name} className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm border border-gray-600" style={{ backgroundColor: item.color }} /><span className="text-xs font-medium text-gray-300">{item.name}</span></div>))}</div>
        </CardContent>
      </Card>
    </div>
  )
}

export function SeverityDistributionChart() {
  const totalVulnerabilities = severityDistribution.reduce((sum, item) => sum + item.value, 0);
  return (
    <Card className="border border-gray-700/50 shadow-xl bg-gradient-to-br from-gray-900/90 to-gray-800/40 backdrop-blur-sm">
      <CardHeader className="pb-4">
        <div className="flex items-center gap-3"><div className="p-2 rounded-lg bg-blue-500/20 border border-blue-500/30"><BarChart3 className="h-5 w-5 text-blue-400" /></div><div><CardTitle className="text-lg font-semibold text-gray-100">Risk Distribution</CardTitle><p className="text-sm text-gray-400">September findings: <span className="font-mono font-medium text-gray-200">{totalVulnerabilities}</span></p></div></div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie 
                data={severityDistribution} 
                cx="50%" 
                cy="50%" 
                outerRadius={100} 
                innerRadius={60} 
                paddingAngle={2} 
                dataKey="value" 
                stroke="#1f2937" 
                strokeWidth={2}
              >
                {severityDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                formatter={(value: any, name: any, props: any) => [
                  `${value} findings`, 
                  props.payload.name
                ]} 
                contentStyle={{ 
                  backgroundColor: '#111827', 
                  border: '1px solid #374151', 
                  borderRadius: '8px', 
                  boxShadow: '0 4px 12px rgb(0 0 0 / 0.3)', 
                  fontSize: '12px', 
                  color: '#f3f4f6' 
                }} 
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="grid grid-cols-2 gap-2 mt-4">{severityDistribution.map((item) => (<div key={item.name} className="flex items-center justify-between p-3 rounded-lg bg-gray-800/50 border border-gray-700/50"><div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-sm border border-gray-600" style={{ backgroundColor: item.color }} /><span className="text-sm font-medium text-gray-200">{item.name}</span></div><div className="flex items-center gap-2"><span className="text-xs font-mono text-gray-400">{item.percentage}</span><Badge variant="secondary" className="text-xs font-mono h-5 px-2 bg-gray-700 text-gray-200 border-gray-600">{item.value}</Badge></div></div>))}</div>
      </CardContent>
    </Card>
  )
}
