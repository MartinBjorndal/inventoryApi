// Packages
require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const compression = require('compression');
const helmet = require('helmet');

// Use 
app.use(express.json());// Allow json
app.use(compression()); // Compress all routes
app.use(helmet());      // Use helmet for protection

// Data users access
const posts = [
  {
    username: 'Kyle',
    title: 'Post 1'
  },
  {
    username: 'Jim',
    title: 'Post 2'
  }
]


// Return posts made by user
app.get('/posts', authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.name))
})


// Authenticate accessToken sent by user
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']      // Get data at the authorization header
  const token = authHeader && authHeader.split(' ')[1]  // Split token from Bearer prefix
  if (token == null) return res.sendStatus(401)        // Check if user didn't send token

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => { // Verify token
    console.log(err)      
    if (err) return res.sendStatus(403)
    req.user = user 
    next()
  })
}



// Listen to port 3000
app.listen(3000)