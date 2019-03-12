/**
 * Module dependencies.
 */
var util = require("util");
var OAuth2Strategy = require("passport-oauth2");
var InternalOAuthError = require("passport-oauth2").InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Mixer authentication strategy authenticates requests by delegating to
 * Mixer using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Mixer application"s client id
 *   - `clientSecret`  your Mixer application"s client secret
 *   - `callbackURL`   URL to which Mixer will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new MixerStrategy({
 *         clientID: "123-456-789",
 *         clientSecret: "shhh-its-a-secret"
 *         callbackURL: "https://www.example.net/auth/mixer/callback"
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || "https://mixer.com/oauth/authorize";
    options.tokenURL = options.tokenURL || "https://mixer.com/api/v1/oauth/token";

    OAuth2Strategy.call(this, options, verify);
    this.name = "mixer";

    this._oauth2.setAuthMethod("OAuth");
    this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Mixer.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `mixer`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get("https://mixer.com/api/v1/users/current", accessToken, function (err, body, res) {
        if (err) { return done(new InternalOAuthError("failed to fetch user profile", err)); }

        try {
            var json = JSON.parse(body);

            var profile = { provider: "mixer" };
            profile.id = json._id;
            profile.username = json.name;
            profile.displayName = json.display_name;
            profile.email = json.email;

            profile._raw = body;
            profile._json = json;

            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    if (typeof options.forceVerify !== "undefined") {
        params.force_verify = !!options.forceVerify;
    }
    return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;