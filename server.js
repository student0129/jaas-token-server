const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
app.use(cors());
app.use(bodyParser.json());

// This is where the APP_ID will be used in the header
const APP_ID = process.env.APP_ID;

// Create the private key string with the BEGIN and END markers
const privateKey = process.env.PRIVATE_KEY;

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

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
