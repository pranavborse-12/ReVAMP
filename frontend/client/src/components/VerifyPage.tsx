import { useState, useEffect } from 'react';
import { useAuth } from '../hooks/useAuth';

export default function VerifyPage() {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [verifying, setVerifying] = useState(false);
  const { session, isAuthenticated, loading, checkAuthStatus, verifyCode, emailHint } = useAuth();

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const sessionParam = urlParams.get('session');

    if (sessionParam && !session) {
      checkAuthStatus(sessionParam);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to main app after successful verification
      window.location.href = '/';
    }
  }, [isAuthenticated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) {
      setError('Please enter a 6-digit code');
      return;
    }

    setVerifying(true);
    setError('');

    try {
      await verifyCode(code);
      // Will redirect via useEffect above
    } catch (err: any) {
      setError(err.message || 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '100vh' 
      }}>
        <div>Loading...</div>
      </div>
    );
  }

  if (!session) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        minHeight: '100vh',
        flexDirection: 'column'
      }}>
        <h2>Session expired</h2>
        <p>Please try signing in again.</p>
        <button onClick={() => window.location.href = '/'}>
          Go back to home
        </button>
      </div>
    );
  }

  return (
    <div style={{ 
      maxWidth: '400px', 
      margin: '100px auto', 
      padding: '20px',
      fontFamily: 'system-ui, -apple-system, sans-serif'
    }}>
      <h2 style={{ textAlign: 'center', marginBottom: '10px' }}>
        Check Your Email
      </h2>
      
      <p style={{ textAlign: 'center', color: '#666', marginBottom: '30px' }}>
        We've sent a verification code to<br />
        <strong>{emailHint}</strong>
      </p>
      
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000"
          style={{ 
            width: '100%', 
            padding: '15px', 
            marginBottom: '15px', 
            textAlign: 'center', 
            fontSize: '24px',
            letterSpacing: '8px',
            border: '2px solid #ddd',
            borderRadius: '8px',
            outline: 'none'
          }}
          maxLength={6}
          required
        />
        
        {error && (
          <p style={{ 
            color: '#dc3545', 
            marginBottom: '15px', 
            padding: '10px',
            backgroundColor: '#f8d7da',
            border: '1px solid #f5c6cb',
            borderRadius: '4px',
            textAlign: 'center'
          }}>
            {error}
          </p>
        )}
        
        <button 
          type="submit" 
          disabled={code.length !== 6 || verifying}
          style={{ 
            width: '100%', 
            padding: '15px', 
            background: code.length === 6 && !verifying ? '#007bff' : '#6c757d', 
            color: 'white', 
            border: 'none', 
            borderRadius: '8px',
            fontSize: '16px',
            cursor: code.length === 6 && !verifying ? 'pointer' : 'not-allowed'
          }}
        >
          {verifying ? 'Verifying...' : 'Verify Code'}
        </button>
      </form>

      <p style={{ 
        textAlign: 'center', 
        marginTop: '20px', 
        fontSize: '14px', 
        color: '#6c757d' 
      }}>
        Didn't receive the code? Check your spam folder.
      </p>
    </div>
  );
}