var express = require('express');
var session = require('express-session');
var config = require('./config');
var Grant = require('grant-express');
var app = express();

function getGrantConfig() {
    return {
        server: config.server,
        "life_engine": config.oauth
    }
}

// Session middleware is required
app.use(session({
    secret: config.session_secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        // secure: true // When hosted via HTTPS
    }
}));

// And so is the "grant" OAuth handler
app.use(new Grant(getGrantConfig()));

// Static files, you really shouldn't serve "." for real uses
app.use(express.static('.'));

// Callback once the OAuth authorization grant flow has been completed
app.get('/oauth/callback', function (req, res) {
    console.log("OAuth callback got data:", req.query);

    var data = {
        "accessToken": req.query.access_token
    };

    res.redirect("/#" + encodeURIComponent(JSON.stringify(data)));
});

app.listen(config.server.port, function () {
    console.log('Express server listening on port ' + config.server.port)
});
