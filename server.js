if (!code) {
    return res.status(400).json({ valid: false });
  }const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// Enhanced CORS configuration
app.use(cors({
  origin: '*', // Allow all origins for now
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));

app.use(bodyParser.json());

// Add explicit OPTIONS handler for preflight requests
app.options('*', cors());

// This is where the APP_ID will be used in the header
const APP_ID = process.env.APP_ID;

// Create the private key string with the BEGIN and END markers
const privateKey = process.env.PRIVATE_KEY;

// Add these new environment variables for access code system
const SECRET_KEY = process.env.SECRET_KEY || "ProMoNtOrY_AI_2025_SecReT";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "YourSecureAdminPassword123";

app.post('/token', (req, res) => {
  const { name, room, email } = req.body;
  
  // Determine if user is moderator based on whether their name includes "taher"
  const isModerator = name && name.toLowerCase().includes('taher');
  
  // Extract the sub value from APP_ID
  const SUB = APP_ID.split('/')[0];
  
  // Generate a random ID for the user (similar to auth0 format)
  const randomId = `auth0|${crypto.randomBytes(12).toString('hex')}`;
  
  const now = Math.floor(Date.now() / 1000);
  
  const payload = {
    aud: 'jitsi',
    iss: 'chat',
    iat: now,
    exp: now + 7200, // 2 hours expiration
    nbf: now - 5,    // Valid 5 seconds before issue time (to account for clock skew)
    sub: SUB,        // The part before the slash in APP_ID
    context: {
      features: {
        livestreaming: isModerator,
        'outbound-call': true,
        'sip-outbound-call': false,
        transcription: true,
        recording: isModerator
      },
      user: {
        'hidden-from-recorder': false,
        moderator: isModerator,
        name: name || 'Guest',
        id: randomId,
        avatar: "",
        email: email || ""
      }
    },
    room: room // || '*'  // Use specific room if provided, otherwise wildcard
  };
  
  const options = {
    algorithm: 'RS256',
    header: {
      kid: APP_ID,  // Full APP_ID including the slash part
      typ: 'JWT',
      alg: 'RS256'
    }
  };
  
  try {
    const token = jwt.sign(payload, privateKey, options);
    
    // For debugging - remove in production
    // const decodedToken = jwt.decode(token, { complete: true });
    // console.log('Header:', JSON.stringify(decodedToken.header, null, 2));
    // console.log('Payload:', JSON.stringify(decodedToken.payload, null, 2));
    
    res.json({ token });
  } catch (error) {
    console.error('JWT signing error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// NEW ENDPOINTS FOR ACCESS CODE SYSTEM

// Admin authentication endpoint
app.post('/admin-auth', (req, res) => {
  // Add CORS headers explicitly
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  const { password } = req.body;
  
  console.log('Admin auth attempt:', { 
    receivedPassword: password ? '[PASSWORD PROVIDED]' : '[NO PASSWORD]',
    expectedPassword: ADMIN_PASSWORD ? '[PASSWORD SET]' : '[NO PASSWORD SET]',
    match: password === ADMIN_PASSWORD
  });
  
  if (password === ADMIN_PASSWORD) {
    console.log('Authentication successful');
    res.json({ authenticated: true });
  } else {
    console.log('Authentication failed');
    res.status(401).json({ authenticated: false });
  }
});

// Generate access code endpoint
app.post('/generate-code', (req, res) => {
  // Add CORS headers explicitly
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  const { clientName, meetingDateTime } = req.body;
  
  if (!clientName || !meetingDateTime) {
    return res.status(400).json({ error: 'Client name and meeting date/time are required' });
  }
  
  try {
    const result = generateAccessCode(clientName, meetingDateTime);
    res.json(result);
  } catch (error) {
    console.error('Code generation error:', error);
    res.status(500).json({ error: 'Failed to generate access code' });
  }
});

// Validate access code endpoint
app.post('/validate-code', (req, res) => {
  // Add CORS headers explicitly
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  const { code, clientName } = req.body;
// Access code generation function
function generateAccessCode(clientName, meetingDateTime) {
  // Use the exact meeting time (not rounded to 2-hour windows)
  const date = new Date(meetingDateTime);
  
  // Create window: 3 minutes before meeting + 2 hours duration
  const windowStart = new Date(date.getTime() - 3 * 60 * 1000); // 3 minutes early
  const windowEnd = new Date(date.getTime() + 2 * 60 * 60 * 1000); // 2 hours after meeting start
  
  // Create seed from exact date/time, client name, and secret
  const dateString = date.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM (include minutes)
  const clientNormalized = clientName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const seed = dateString + clientNormalized + SECRET_KEY;
  
  // Simple hash function to generate code
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    const char = seed.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  // Convert to 6-digit code
  const code = Math.abs(hash % 900000) + 100000; // Ensures 6 digits
  
  return {
    code: code.toString(),
    windowStart: windowStart,
    windowEnd: windowEnd,
    meetingStart: date
  };
}
  
  const now = new Date();
  
  try {
    // For validation, we need to check if any meeting window is currently active
    // Since we don't know the exact meeting time, we check recent possible meeting times
    
    // Check meetings that could have started in the last 2 hours and 3 minutes
    // This covers any meeting that might currently be in its valid window
    const checkDuration = 2 * 60 + 3; // 2 hours 3 minutes in minutes
    
    for (let minutesAgo = 0; minutesAgo <= checkDuration; minutesAgo += 1) {
      const possibleMeetingTime = new Date(now.getTime() - minutesAgo * 60 * 1000);
      
      // Generate code for this possible meeting time
      const testCode = generateAccessCode(clientName || '', possibleMeetingTime);
      
      // Check if this meeting's window is currently active
      if (now >= testCode.windowStart && now <= testCode.windowEnd) {
        if (code === testCode.code) {
          return res.json({ 
            valid: true,
            meetingStart: testCode.meetingStart,
            windowEnd: testCode.windowEnd
          });
        }
      }
    }
    
    // Also check some common test client names for demo purposes
    const commonClients = ['client', 'demo', 'test', 'meeting'];
    for (const client of commonClients) {
      for (let minutesAgo = 0; minutesAgo <= checkDuration; minutesAgo += 5) { // Check every 5 minutes for performance
        const possibleMeetingTime = new Date(now.getTime() - minutesAgo * 60 * 1000);
        const testCode = generateAccessCode(client, possibleMeetingTime);
        
        if (now >= testCode.windowStart && now <= testCode.windowEnd) {
          if (code === testCode.code) {
            return res.json({ 
              valid: true,
              meetingStart: testCode.meetingStart,
              windowEnd: testCode.windowEnd
            });
          }
        }
      }
    }
    
    res.json({ valid: false, reason: 'No active meeting found for this code' });
  } catch (error) {
    console.error('Code validation error:', error);
    res.status(500).json({ valid: false, reason: 'Validation error' });
  }
});

// Health check endpoint (optional)
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
