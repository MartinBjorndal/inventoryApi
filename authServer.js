// Packages
require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const compression = require('compression');
const helmet = require('helmet');

// Use 
app.use(express.json());// Allow json
app.use(compression()); // Compress all routes
app.use(helmet());      // Use helmet for protection

// Temp alternative to DB
let refreshTokens = []
let users = []



// Generate new accessToken from refreshToken
app.post('/token', (req, res) => {
  const refreshToken = req.body.token
  if (refreshToken == null) return res.sendStatus(401)    // Check if user sends refreshToken
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)      // Check if refreshToken is valid
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {     
    if (err) return res.sendStatus(403)           
    const accessToken = generateAccessToken({ name: user.name })        // Generate new accessToken and return it
    res.json({ accessToken: accessToken })
  })
})

// Logout user, invalidate refresh token
app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})

// Authenticate user and return tokens
app.post('/login', (req, res) => {
  const user = users.find(user => user.name = req.body.name);
    if (user == null) {
        // Username not found
        return res.status(400).send("Cannot find user");
    }
    try {
        // Username found, checking password
        if( await bcrypt.compare(req.body.pin, user.pin)){
          // Password matches, return tokens
          const username = req.body.username
          const user = { name: username }
          const accessToken = generateAccessToken(user)
          const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
          refreshTokens.push(refreshToken)
          res.json({ accessToken: accessToken, refreshToken: refreshToken })
        } else { 
          // Password doesn't match
          res.send("Not Allowed") 
        };
    } catch {
      // Something went wrong
      res.status(500).send();
    }  
})


// Register new user
app.post("/users", async (req, res) =>{
  try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(req.body.password, 12);
      const user = { name: req.body.name, password: hashedPassword }
      users.push(user);  // Add user to users array
      res.status(201).send();   
  } catch {
      res.status(500).send();   // Something went wrong
  }   
})

function generateAccessToken(user) {
  // Return accessToken, expires in =>                                  ↓
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}

app.listen(4000)