// Don't actually serve a config with session secret etc. to the clients

const port = 8080;

const config = {
    "server": {
        "protocol": "http",
        "host": "localhost:" + port,
        "port": port
    },
    "oauth": {
        "authorize_url": "url to authorization page",
        "access_url": "url to convert authorization token",
        "client_id": "your OAuth client ID",
        "client_secret": "your OAuth client secret",
        "callback": "/oauth/callback",
        "oauth": 2
    },
    "apiUrl": "URL to Life Engine API",
    // Generate a random string here
    "session_secret": "1498662292588"
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = config;
}
