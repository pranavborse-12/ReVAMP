import { Badge } from '../components/ui/badge';

export type SecurityLevel = 'critical' | 'medium' | 'low';

interface SecurityLevelProps {
  level: SecurityLevel;
  showDot?: boolean;
  showBadge?: boolean;
  dotSize?: 'sm' | 'md' | 'lg';
  className?: string;
  'data-testid'?: string;
}

export function SecurityLevelIndicator({
  level,
  showDot = true,
  showBadge = false,
  dotSize = 'md',
  className = '',
  'data-testid': testId
}: SecurityLevelProps) {
  const getColorVar = (level: SecurityLevel) => {
    switch (level) {
      case 'critical':
        return 'var(--critical)';
      case 'medium':
        return 'var(--medium)';
      case 'low':
        return 'var(--low)';
      default:
        return 'var(--low)';
    }
  };

  const getBadgeVariant = (level: SecurityLevel) => {
    switch (level) {
      case 'critical':
        return 'destructive';
      case 'medium':
        return 'secondary';
      case 'low':
        return 'outline';
      default:
        return 'outline';
    }
  };

  const getDotSize = (size: 'sm' | 'md' | 'lg') => {
    switch (size) {
      case 'sm':
        return 'h-2 w-2';
      case 'md':
        return 'h-3 w-3';
      case 'lg':
        return 'h-4 w-4';
      default:
        return 'h-3 w-3';
    }
  };

  const getLevelText = (level: SecurityLevel) => {
    switch (level) {
      case 'critical':
        return 'Critical';
      case 'medium':
        return 'Medium';
      case 'low':
        return 'Low';
      default:
        return 'Low';
    }
  };

  return (
    <div className={`flex items-center gap-2 ${className}`} data-testid={testId}>
      {showDot && (
        <div
          className={`${getDotSize(dotSize)} rounded-full`}
          style={{ backgroundColor: `hsl(${getColorVar(level)})` }}
          data-testid={`dot-${level}`}
        />
      )}
      {showBadge && (
        <Badge variant={getBadgeVariant(level)} className="text-xs" data-testid={`badge-${level}`}>
          {getLevelText(level)}
        </Badge>
      )}
    </div>
  );
}

interface SecurityLevelTextProps {
  level: SecurityLevel;
  className?: string;
  'data-testid'?: string;
}

export function SecurityLevelText({
  level,
  className = '',
  'data-testid': testId
}: SecurityLevelTextProps) {
  const getLevelText = (level: SecurityLevel) => {
    switch (level) {
      case 'critical':
        return 'Critical Risk Level';
      case 'medium':
        return 'Medium Risk Level';
      case 'low':
        return 'Low Risk Level';
      default:
        return 'Low Risk Level';
    }
  };

  return (
    <span className={`text-sm text-muted-foreground ${className}`} data-testid={testId}>
      {getLevelText(level)}
    </span>
  );
}