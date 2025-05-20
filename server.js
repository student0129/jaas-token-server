const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(bodyParser.json());
const APP_ID = process.env.APP_ID;
const PRIVATE_KEY = process.env.PRIVATE_KEY; // This must be an RS256 private key

app.post('/token', (req, res) => {
  const { name, room } = req.body;
  
  // Determine if user is moderator based on whether their name includes "taher"
  const isModerator = name && name.toLowerCase().includes('taher');
  
  // Extract the sub value from APP_ID
  const SUB = APP_ID.split('/')[0];
  
  const now = Math.floor(Date.now() / 1000);
  
  const payload = {
    aud: 'jitsi',
    iss: 'chat',
    iat: now,
    exp: now + 3600,
    nbf: now - 5,
    sub: SUB,
    room: room || '*',
    context: {
      features: {
        livestreaming: false,
        'outbound-call': false,
        'sip-outbound-call': false,
        transcription: false,
        recording: false
      },
      user: {
        'hidden-from-recorder': false,
        moderator: isModerator,
        name: name || 'Guest',
        id: `user-${Date.now()}`,
        avatar: "",
        email: ""
      }
    }
  };
  
  const token = jwt.sign(payload, PRIVATE_KEY, {
    algorithm: 'RS256',
    header: {
      kid: APP_ID,
      typ: 'JWT'
    }
  });
  
  res.send({ token });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
