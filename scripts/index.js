const crypto = require("crypto");
const Vue = require("vue");
const io = require("socket.io-client");

function createDHInstance() {
	/* https://www.ietf.org/rfc/rfc3526.txt */

	const prime = `
	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
	E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
	DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
	15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
	ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
	ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
	F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
	BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
	43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
	`.replace(/[^A-Fa-f0-9]/g, "").toLowerCase();

	console.log(`Prime is ${prime.length * 4} bits long`);

	return crypto.createDiffieHellman(prime, "hex");
}

function sha256(data) {
	const hash = crypto.createHash("sha256");
	hash.update(data);
	return hash.digest();
}

let socket, chatId, userKey, sharedSecret, sharedKey;
let messagesWaiting = 0;

function encrypt(data) {
	if(!(sharedKey instanceof Buffer)) {
		throw new Error("Shared key not defined.")
	}

	if(sharedKey.length != 32) {
		throw new Error("Shared key not proper length.");
	}

	const iv = sha256(crypto.randomBytes(64)).slice(0, 16);
	const cipher = crypto.createCipheriv("aes-256-cbc", sharedKey, iv);

	return Buffer.concat([ iv, cipher.update(data), cipher.final() ]).toString("base64");
}

function decrypt(data) {
	data = Buffer.from(data, "base64");
	const iv = data.slice(0, 16);
	data = data.slice(16);

	const decipher = crypto.createDecipheriv("aes-256-cbc", sharedKey, iv);

	return decipher.update(data, "base64", "utf8") + decipher.final("utf8");
}

const app = window.app = new Vue({
	el: "#app",
	data: {
		setup: false,
		chatId: false,
		publicKey: "",
		recipientPublicKey: "",
		messages: [],
		auth: false,
		newMessageText: "",
		href: location.href
	},
	methods: {
		startSetup() {
			userKey = createDHInstance();
			userKey.generateKeys();

			console.log(`DH Public Key: ${userKey.getPrivateKey().toString("base64")}`);
			chatId = sha256(crypto.randomBytes(64));
			console.log(`Initial Chat ID: ${chatId.toString("base64")}`)

			app.publicKey = Buffer.concat([ chatId, userKey.getPublicKey() ]).toString("base64");
			console.log(`Public Key: ${app.publicKey}`);

			this.setup = true;
		},
		keyExchange() {
			console.log(`Recipient Public Key: ${app.recipientPublicKey}`);
			const data = Buffer.from(app.recipientPublicKey, "base64");
			const recipientKey = data.slice(32);

			console.log(`Recipient DH Public Key: ${recipientKey.toString("base64")}`);

			for(let i = 0; i < 32; i++) {
				chatId[i] ^= data[i];
			}

			console.log(`Final Chat ID: ${chatId.toString("base64")}`)

			sharedSecret = userKey.computeSecret(recipientKey);
			sharedKey = sha256(sharedSecret);
			app.auth = true;

			socket = io(location.origin);
			socket.emit("id", chatId.toString("base64"));

			const colors = [ "#e74c3c", "#3498db" ];

			socket.on("message", message => {
				app.messages.push({
					text: decrypt(message.text),
					color: colors[message.user]
				});

				const messagesElement = document.querySelector("#messages");

				setTimeout(() => {
					messagesElement.scrollTop = messagesElement.scrollHeight + 100;
				}, 0);

				if(document.hidden) {
					messagesWaiting++;
					document.title = `(${messagesWaiting}) facefuck`;
				}
			});
		},
		sendMessage() {
			socket.emit("message", encrypt(app.newMessageText));
			app.newMessageText = "";
		}
	}
});


document.addEventListener("visibilitychange", () => {
	if(!document.hidden) {
		messagesWaiting = 0;
		document.title = "facefuck";
	}
}, false);
