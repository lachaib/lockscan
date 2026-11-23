/** Environment variable names that carry CI, registry or cloud credentials. */
export const CI_ENV_NAMES = [
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_RUNTIME_URL',
  'ACTIONS_CACHE_URL',
  'ACTIONS_RESULTS_URL',
  'GITLAB_TOKEN',
  'CI_JOB_TOKEN',
  'CI_REGISTRY_PASSWORD',
  'CI_DEPLOY_PASSWORD',
  'CIRCLE_TOKEN',
  'SYSTEM_ACCESSTOKEN',
  'NPM_TOKEN',
  'NODE_AUTH_TOKEN',
  'YARN_NPM_AUTH_TOKEN',
  'PYPI_TOKEN',
  'TWINE_PASSWORD',
  'COMPOSER_AUTH',
  'PACKAGIST_TOKEN',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'AZURE_CLIENT_SECRET',
  'VERCEL_TOKEN',
  'CODECOV_TOKEN',
  'FIREBASE_TOKEN',
  'HEROKU_API_KEY',
  'SENTRY_AUTH_TOKEN',
  'DOCKER_PASSWORD',
] as const;

/** Regex source matching any name in CI_ENV_NAMES; callers add their own trailing boundary. */
export const CI_NAME = `(?:${CI_ENV_NAMES.join('|')})`;

/** Regex source for other secret-looking names (`*_TOKEN`, `*_SECRET`, …) that are not in CI_ENV_NAMES. */
export const GENERIC_SECRET_NAME = `(?!${CI_NAME}(?![\\w$]))[A-Z][A-Z0-9_]*_(?:TOKEN|SECRET|PASSWORD|API_KEY)`;
