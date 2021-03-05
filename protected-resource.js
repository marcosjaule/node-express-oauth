const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const { timeout } = require("./utils")
const jwt = require('jsonwebtoken')
const { stringify } = require("querystring")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/user-info', (request, response) => {
	if (request.headers.authorization) {
		const token = request.headers.authorization;
		const slicedToken = token.slice(7, token.length)
		try {
			const obj = jwt.verify(slicedToken, config.publicKey);
			const scopes = obj.scope.split(" ").map(x => x.slice(11, x.length))
			const y = {}
			const res = scopes.reverse().map((x) => {
				y[x] = users[obj.userName][x]
			})
			response.status(200).json(y).end();
		} catch (error) {
			response.status(401).end();
		}
	} else {
		response.status(401).end()
	}
})

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
