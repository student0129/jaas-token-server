const express = require('express');
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

// Environment variables
const APP_ID = process.env.APP_ID;
const privateKey = process.env.PRIVATE_KEY;
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Original token endpoint
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
    room: room
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
    res.json({ token });
  } catch (error) {
    console.error('JWT signing error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Access code generation function
function generateAccessCode(clientName, meetingDateTime) {
  const date = new Date(meetingDateTime);
  
  // Create window: 3 minutes before meeting + 2 hours duration
  const windowStart = new Date(date.getTime() - 3 * 60 * 1000); // 3 minutes early
  const windowEnd = new Date(date.getTime() + 2 * 60 * 60 * 1000); // 2 hours after meeting start
  
  // Encode meeting timestamp in the code
  // Use minutes since epoch to make it shorter (divide by 60000)
  const meetingTimestamp = Math.floor(date.getTime() / 60000); // Minutes since epoch
  
  // Create seed from client name and secret (timestamp will be encoded separately)
  const clientNormalized = clientName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const seed = clientNormalized + SECRET_KEY;
  
  // Generate base hash
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    const char = seed.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  
  // Create a 4-digit base code from hash
  const baseCode = Math.abs(hash % 9000) + 1000; // 4 digits: 1000-9999
  
  // Encode timestamp in last 4 digits
  // Use last 4 digits of timestamp for time encoding
  const timeCode = meetingTimestamp % 10000; // Last 4 digits
  
  // Combine: 4 digits base + 4 digits time = 8 digit code
  const fullCode = baseCode.toString() + timeCode.toString().padStart(4, '0');
  
  return {
    code: fullCode,
    windowStart: windowStart,
    windowEnd: windowEnd,
    meetingStart: date,
    encodedTimestamp: meetingTimestamp
  };
}

// Decode meeting time from access code
function decodeMeetingTime(code, clientName) {
  if (code.length !== 8) {
    return null;
  }
  
  // Extract time code (last 4 digits)
  const timeCode = parseInt(code.slice(-4));
  
  // We need to find the full timestamp that ends with these 4 digits
  // Check recent time windows (last few days worth of minutes)
  const now = Date.now();
  const currentMinutes = Math.floor(now / 60000);
  
  // Check up to 7 days ago (7 * 24 * 60 = 10080 minutes)
  for (let minutesAgo = 0; minutesAgo <= 10080; minutesAgo++) {
    const candidateMinutes = currentMinutes - minutesAgo;
    
    if (candidateMinutes % 10000 === timeCode) {
      // Found a match! Verify it generates the same code
      const candidateDate = new Date(candidateMinutes * 60000);
      const testCode = generateAccessCode(clientName, candidateDate);
      
      if (testCode.code === code) {
        return candidateDate;
      }
    }
  }
  
  return null;
}

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
  
  if (!code) {
    return res.status(400).json({ valid: false });
  }
  
  console.log('Validation attempt:', {
    code: code,
    clientName: clientName,
    currentTime: new Date().toISOString()
  });
  
  try {
    // Decode the meeting time from the access code
    const meetingTime = decodeMeetingTime(code, clientName || '');
    
    if (!meetingTime) {
      console.log('Could not decode meeting time from code');
      return res.json({ valid: false, reason: 'Invalid code format or expired' });
    }
    
    console.log('Decoded meeting time:', meetingTime.toISOString());
    
    // Generate the expected code for this meeting time
    const expectedCodeData = generateAccessCode(clientName || '', meetingTime);
    
    // Check if we're within the valid window
    const now = new Date();
    const isWithinWindow = now >= expectedCodeData.windowStart && now <= expectedCodeData.windowEnd;
    
    console.log('Validation details:', {
      expectedCode: expectedCodeData.code,
      receivedCode: code,
      windowStart: expectedCodeData.windowStart.toISOString(),
      windowEnd: expectedCodeData.windowEnd.toISOString(),
      currentTime: now.toISOString(),
      isWithinWindow: isWithinWindow,
      codesMatch: expectedCodeData.code === code
    });
    
    if (expectedCodeData.code === code && isWithinWindow) {
      return res.json({ 
        valid: true,
        meetingStart: expectedCodeData.meetingStart,
        windowEnd: expectedCodeData.windowEnd
      });
    }
    
    // Also try with common test client names
    const commonClients = ['client', 'demo', 'test', 'meeting'];
    for (const testClient of commonClients) {
      const testMeetingTime = decodeMeetingTime(code, testClient);
      if (testMeetingTime) {
        const testCodeData = generateAccessCode(testClient, testMeetingTime);
        const testIsWithinWindow = now >= testCodeData.windowStart && now <= testCodeData.windowEnd;
        
        if (testCodeData.code === code && testIsWithinWindow) {
          return res.json({ 
            valid: true,
            meetingStart: testCodeData.meetingStart,
            windowEnd: testCodeData.windowEnd
          });
        }
      }
    }
    
    res.json({ 
      valid: false, 
      reason: isWithinWindow ? 'Code mismatch' : 'Outside valid time window'
    });
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
