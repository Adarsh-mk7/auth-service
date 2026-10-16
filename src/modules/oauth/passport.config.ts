import passport from 'passport';
import { Strategy as GoogleStrategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { config } from '../../config/environment';
import { OAuthService, GoogleProfileInput } from './oauth.service';
import { RepositoryContainer, getRepositories } from '../../repositories';

export const isGoogleOAuthConfigured = (): boolean => {
  return (
    Boolean(config.GOOGLE_CLIENT_ID) &&
    Boolean(config.GOOGLE_CLIENT_SECRET) &&
    !config.GOOGLE_CLIENT_ID?.includes('your_google_client_id')
  );
};

export const configurePassport = (repos?: RepositoryContainer): void => {
  if (!isGoogleOAuthConfigured()) {
    return;
  }

  const repositoryContainer = repos || getRepositories();
  const oauthService = new OAuthService(repositoryContainer);

  passport.use(
    new GoogleStrategy(
      {
        clientID: config.GOOGLE_CLIENT_ID!,
        clientSecret: config.GOOGLE_CLIENT_SECRET!,
        callbackURL: config.GOOGLE_CALLBACK_URL,
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, profile: Profile, done: VerifyCallback) => {
        try {
          const email = profile.emails?.[0]?.value;
          const isEmailVerified = Boolean(profile.emails?.[0]?.verified ?? true);

          if (!email) {
            return done(new Error('No email found in Google profile'));
          }

          const googleInput: GoogleProfileInput = {
            id: profile.id,
            email,
            name: profile.displayName || `${profile.name?.givenName || ''} ${profile.name?.familyName || ''}`.trim(),
            isEmailVerified,
          };

          const ipAddress = req.ip || req.socket.remoteAddress;
          const userAgent = req.headers['user-agent'];

          const result = await oauthService.handleGoogleProfile(googleInput, ipAddress, userAgent);
          return done(null, result);
        } catch (error) {
          return done(error as Error, undefined);
        }
      }
    )
  );
};
