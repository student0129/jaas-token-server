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
  const { name, isModerator } = req.body;

  const payload = {
    aud: 'jitsi',
    iss: APP_ID,
    sub: APP_ID,
    room: '*',
    context: {
      user: {
        name: name || 'Guest'
      }
    },
    moderator: !!isModerator,
    exp: Math.floor(Date.now() / 1000) + (60 * 60)
  };

  const token = jwt.sign(payload, APP_SECRET);
  res.send({ token });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
