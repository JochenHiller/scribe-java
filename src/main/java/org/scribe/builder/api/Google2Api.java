package org.scribe.builder.api;

import static org.scribe.utils.URLUtils.formURLEncode;

import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.JsonTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Verb;
import org.scribe.utils.Preconditions;

public class Google2Api extends DefaultApi20 {
	private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth?client_id=%s&redirect_uri=%s&response_type=code";
	private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL
			+ "&scope=%s";

	@Override
	public String getAccessTokenEndpoint() {
		return "https://accounts.google.com/o/oauth2/token?grant_type=authorization_code";
	}

	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new JsonTokenExtractor();
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		Preconditions.checkValidUrl(config.getCallback(),
				"Must provide a valid url as callback.");

		// Append scope if present
		if (config.hasScope()) {
			return String.format(SCOPED_AUTHORIZE_URL, config.getApiKey(),
					formURLEncode(config.getCallback()),
					formURLEncode(config.getScope()));
		} else {
			return String.format(AUTHORIZE_URL, config.getApiKey(),
					formURLEncode(config.getCallback()));
		}
	}

	public Verb getAccessTokenVerb() {
		return Verb.POST;
	}
}
