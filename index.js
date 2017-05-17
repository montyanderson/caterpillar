const crypto = require("crypto");
const express = require("express");
const app = express();
const server = require("http").Server(app);
const io = require("socket.io")(server);

app.use(express.static(__dirname + "/public"));

function sha256(data) {
	const hash = crypto.createHash("sha256");
	hash.update(data);
	return hash.digest();
}

app.get("/new", (req, res) => {
	const id = sha256(crypto.randomBytes(64))
		.toString("base64")
		.replace(new RegExp("+", "g"), "-")
		.replace(new RegExp("/", "g"), "_");

	res.redirect("/?" + id);
});

const chats = new Map();

io.on("connection", socket => {
	let _id;
	let users;

	socket.on("id", id => {
		_id = id;

		if(!chats.has(id)) {
			users = [];
			chats.set(id, users);
		} else {
			users = chats.get(id);
		}

		if(users.length > 1) {
			users.shift();
		}

		users.push(socket);
		console.log(id, users);
	});

	socket.on("message", message => {
		console.log(message);

		if(users) {
			users.forEach(user => {
				user.emit("message", {
					text: message,
					user: users.indexOf(socket)
				});
			});
		}
	});

	socket.on("disconnect", () => {
		if(users) {
			users.splice(users.indexOf(socket), 1);

			if(users.length < 1) {
				chats.delete();
			}
		}
	});
});

server.listen(process.argv[2] || 8080, process.argv[3] || "0.0.0.0");
