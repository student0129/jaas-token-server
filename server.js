const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(bodyParser.json());
const APP_ID = process.env.APP_ID;
const APP_SECRET = process.env.APP_SECRET;

app.post('/token', (req, res) => {
  const { name } = req.body;
  
  // Determine if user is moderator based on whether their name includes "taher"
  const isModerator = name && name.toLowerCase().includes('taher');
  
  // Extract the sub value from APP_ID (everything before the first slash)
  const SUB = APP_ID.split('/')[0];
  
  const payload = {
    aud: 'jitsi',
    iss: 'chat',
    sub: SUB,
    room: '*',
    context: {
      user: {
        name: name || 'Guest',
        moderator: isModerator // Set based on name check for "taher"
      },
      features: {
        livestreaming: false,
        recording: false
      }
    },
    exp: Math.floor(Date.now() / 1000) + (60 * 60)
  };
  
  const token = jwt.sign(payload, APP_SECRET, {
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
