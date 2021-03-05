const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")

const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")
const { url } = require("inspector")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/authorize', (request, response) => {
	try {
		const { client_id, scope } = request.query
		if (clients[client_id] && scope) {
			const perms = scope.split(" ");

			if (containsAll(clients[client_id].scopes, perms)) {
				const ID = randomString()
				requests[ID] = request.query
				response.status(200)
				response.render("login", { client: clients[client_id], scope: scope, requestId: ID })
				return;
			}
		}
		response.status(401).end()
	} catch (error) {
		console.log(error);
		response.status(500).end()
	}


})

app.post('/approve', (request, response) => {
	const { userName, password, requestId } = request.body
	if (users[userName] && users[userName] === password) {
		if (!requests[requestId]) {
			response.status(401).end();
		}
		const rq = requests[requestId];
		delete requests[requestId]
		const random = randomString();

		authorizationCodes[random] = {
			clientReq: rq,
			userName
		}
		const myURL = new URL(rq.redirect_uri)
		myURL.searchParams.append('code', random)
		myURL.searchParams.append('state', rq.state)
		response.status(200).redirect(myURL.href);

		return
	}
	response.status(401).end();
})



app.post('/token', (request, response) => {
	if (request.headers.authorization) {
		const credential = decodeAuthCredentials(request.headers.authorization)
		if (credential.clientSecret !== clients[credential.clientId].clientSecret) {
			response.status(401).end()
		}
		//console.log(credential.clientSecret === clients[credential.clientId].clientSecret)
		if (!authorizationCodes[request.body.code]) {
			response.status(401).end()
		}
		const body = authorizationCodes[request.body.code];
		delete authorizationCodes[request.body.code]
		const res = jwt.sign({ userName: body.userName, scope: body.clientReq.scope }, config.privateKey, { algorithm: "RS256" })
		response.status(200).json({ "access_token": res, "token_type": "Bearer" }).end()
	} else {
		response.status(401).end()
	}
})


const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
	console.log("Server UP")
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
