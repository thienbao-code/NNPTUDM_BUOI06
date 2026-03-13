const bcrypt = require("bcrypt")

const password = bcrypt.hashSync("123456",10)

const users = [
{
id:1,
username:"admin",
password:password
}
]

module.exports = users