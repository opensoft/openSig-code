// SPDX-License-Identifier: Apache-2.0
//
// Operator authentication and authorization (T005). There is no operator browser session:
// operators authenticate with bearer access tokens only.

export { ConfigError, loadOperatorAuthConfig, MAX_CLOCK_SKEW_SECONDS } from './config.ts';
export type { OperatorAuthConfig, OperatorAuthInput, OperatorRole, PrincipalKind, TenantIdentityInput } from './config.ts';
export { SUPPORTED_ALGORITHMS } from './jwt.ts';
export { authorize, operationScheme, ROLE_MATRIX } from './matrix.ts';
export type { AuthorizationResult, MatrixEntry, OperationId, Scheme } from './matrix.ts';
export { createOperatorAuthenticator } from './operator.ts';
export type { AuthenticationResult, HeaderBag, OperatorAuthenticator, OperatorPrincipal } from './operator.ts';
