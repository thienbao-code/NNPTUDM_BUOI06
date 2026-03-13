const express = require("express")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const fs = require("fs")
const bodyParser = require("body-parser")

const users = require("./users")

const app = express()
app.use(bodyParser.json())

const privateKey = fs.readFileSync("private.key")
const publicKey = fs.readFileSync("public.key")

function authenticateToken(req,res,next){

const authHeader = req.headers["authorization"]
const token = authHeader && authHeader.split(" ")[1]

if(!token){
return res.status(401).json({message:"Token required"})
}

jwt.verify(token,publicKey,{algorithms:["RS256"]},(err,user)=>{

if(err){
return res.status(403).json({message:"Invalid token"})
}

req.user = user
next()

})

}

app.post("/login", async (req,res)=>{

const {username,password} = req.body

const user = users.find(u=>u.username===username)

if(!user){
return res.status(400).json({message:"User not found"})
}

const match = await bcrypt.compare(password,user.password)

if(!match){
return res.status(400).json({message:"Wrong password"})
}

const token = jwt.sign(
{id:user.id,username:user.username},
privateKey,
{
algorithm:"RS256",
expiresIn:"1h"
}
)

res.json({token})

})

app.get("/me", authenticateToken, (req,res)=>{

res.json(req.user)

})

app.post("/changepassword", authenticateToken, async (req,res)=>{

const {oldpassword,newpassword} = req.body

if(!newpassword || newpassword.length < 6){
return res.status(400).json({message:"New password must be >=6"})
}

const user = users.find(u=>u.id===req.user.id)

const match = await bcrypt.compare(oldpassword,user.password)

if(!match){
return res.status(400).json({message:"Old password incorrect"})
}

const hashed = await bcrypt.hash(newpassword,10)

user.password = hashed

res.json({message:"Password changed successfully"})

})
app.listen(3000,()=>{
console.log("Server running on port 3000")
})