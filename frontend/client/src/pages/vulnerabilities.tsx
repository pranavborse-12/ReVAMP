import { Card, CardContent } from "../components/ui/card";

export default function Vulnerabilities() {
  return (
    <div className="p-4">
      <Card>
        <CardContent>
          <h2 className="text-lg font-semibold">Vulnerabilities</h2>
          <p className="text-sm text-muted-foreground">Vulnerability list and details.</p>
        </CardContent>
      </Card>
    </div>
  );
}
