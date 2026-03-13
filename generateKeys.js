const crypto = require("crypto")
const fs = require("fs")

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
})

fs.writeFileSync(
  "private.key",
  privateKey.export({
    type: "pkcs1",
    format: "pem",
  })
)

fs.writeFileSync(
  "public.key",
  publicKey.export({
    type: "pkcs1",
    format: "pem",
  })
)

console.log("RSA keys generated!")