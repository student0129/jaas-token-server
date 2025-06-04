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
const HOST_NAME = process.env.HOST_NAME;

// Original token endpoint
app.post('/token', (req, res) => {
  const { name, room, email } = req.body;
  
  // Determine if user is moderator based on whether their name includes HOST_NAME
  const isModerator = name && name.toLowerCase().includes(HOST_NAME.toLowerCase());
  
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
        moderator: isModerator ? 'true' : 'false',
        // role: isModerator ? 'moderator' : 'participant', // Add explicit role
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
  // Ensure we're working with a proper UTC date
  const utcDate = new Date(meetingDateTime);
  
  console.log('generateAccessCode input:', {
    input: meetingDateTime,
    parsedDate: utcDate.toISOString(),
    isUTC: 'Should be UTC'
  });
  
  // Create window: 3 minutes before meeting + 2 hours duration (all in UTC)
  const windowStart = new Date(utcDate.getTime() - 3 * 60 * 1000); // 3 minutes early
  const windowEnd = new Date(utcDate.getTime() + 2 * 60 * 60 * 1000); // 2 hours after meeting start
  
  // Encode meeting timestamp in the code (using UTC time)
  const meetingTimestamp = Math.floor(utcDate.getTime() / 60000); // Minutes since epoch (UTC)
  
  // Create seed from ONLY the UTC timestamp and secret key (no client name)
  const utcDateString = utcDate.toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM (UTC)
  const seed = utcDateString + SECRET_KEY;
  
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
  const timeCode = meetingTimestamp % 10000; // Last 4 digits
  
  // Combine: 4 digits base + 4 digits time = 8 digit code
  const fullCode = baseCode.toString() + timeCode.toString().padStart(4, '0');
  
  console.log('Code generation (UTC-based):', {
    meetingTimeUTC: utcDate.toISOString(),
    meetingTimestamp: meetingTimestamp,
    baseCode: baseCode,
    timeCode: timeCode,
    fullCode: fullCode,
    windowStartUTC: windowStart.toISOString(),
    windowEndUTC: windowEnd.toISOString()
  });
  
  return {
    code: fullCode,
    windowStart: windowStart,
    windowEnd: windowEnd,
    meetingStart: utcDate,
    encodedTimestamp: meetingTimestamp
  };
}

// Decode meeting time from access code (UTC-based)
function decodeMeetingTime(code) {
  if (code.length !== 8) {
    console.log('Invalid code length:', code.length);
    return null;
  }
  
  // Extract time code (last 4 digits)
  const timeCode = parseInt(code.slice(-4));
  console.log('Extracted time code:', timeCode);
  
  // We need to find the full UTC timestamp that ends with these 4 digits
  const nowUTC = new Date(); // This is already UTC
  const currentMinutesUTC = Math.floor(nowUTC.getTime() / 60000);
  
  console.log('Current UTC time:', nowUTC.toISOString());
  console.log('Current minutes since epoch (UTC):', currentMinutesUTC);
  console.log('Looking for UTC minutes ending in:', timeCode);
  
  // Check up to 24 hours ago and 24 hours ahead (in UTC)
  for (let minutesOffset = -1440; minutesOffset <= 1440; minutesOffset++) {
    const candidateMinutesUTC = currentMinutesUTC + minutesOffset;
    
    if (candidateMinutesUTC % 10000 === timeCode) {
      console.log('Found candidate UTC minutes:', candidateMinutesUTC);
      
      // Found a match! Create UTC date
      const candidateUTCDate = new Date(candidateMinutesUTC * 60000);
      console.log('Candidate UTC date:', candidateUTCDate.toISOString());
      
      try {
        // Generate test code using this UTC time
        const testCode = generateAccessCode('', candidateUTCDate.toISOString());
        console.log('Generated test code:', testCode.code, 'vs received:', code);
        
        if (testCode.code === code) {
          console.log('Successfully decoded UTC meeting time:', candidateUTCDate.toISOString());
          return candidateUTCDate;
        }
      } catch (error) {
        console.log('Error generating test code:', error);
      }
    }
  }
  
  console.log('Could not find matching UTC timestamp for time code:', timeCode);
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
  
  console.log('Code generation request:', {
    clientName: clientName,
    meetingDateTime: meetingDateTime,
    currentServerTime: new Date().toISOString()
  });
  
  try {
    // Parse the datetime - it comes from HTML datetime-local input
    // which gives us local time without timezone info
    const meetingDate = new Date(meetingDateTime);
    
    console.log('Parsed meeting date:', {
      original: meetingDateTime,
      parsed: meetingDate.toISOString(),
      localString: meetingDate.toString()
    });
    
    const result = generateAccessCode(clientName, meetingDate);
    
    console.log('Generated code result:', {
      code: result.code,
      meetingStart: result.meetingStart.toISOString(),
      windowStart: result.windowStart.toISOString(),
      windowEnd: result.windowEnd.toISOString()
    });
    
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
    // Decode the meeting time from the access code (no client name needed)
    const meetingTime = decodeMeetingTime(code);
    
    if (!meetingTime) {
      console.log('Could not decode meeting time from code');
      return res.json({ valid: false, reason: 'Invalid code format or expired' });
    }
    
    console.log('Decoded meeting time:', meetingTime.toISOString());
    
    // Generate the expected code for this meeting time (client-independent)
    const expectedCodeData = generateAccessCode('', meetingTime);
    
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
