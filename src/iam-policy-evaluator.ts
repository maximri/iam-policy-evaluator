import { readFileSync } from 'node:fs';

export interface IAMStatement {
  Sid?: string;
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource: string | string[];
}

export interface IAMPolicy {
  Version: string;
  Statement: IAMStatement[];
}

export function evaluateAccessFile(
  policyFilePath: string,
  requestedAction: string,
  requestedResource: string,
): boolean {
  const policyJson = readFileSync(policyFilePath, 'utf8');
  const policy = JSON.parse(policyJson) as IAMPolicy;

  return evaluateAccess(policy, requestedAction, requestedResource);
}

export function evaluateAccess(
  policy: IAMPolicy,
  requestedAction: string,
  requestedResource: string,
): boolean {
  if (!policy.Statement) {
    return false;
  }

  const allowedStatements = policy.Statement.filter((statement) => statement.Effect === 'Allow');
  const deniedStatements = policy.Statement.filter((statement) => statement.Effect === 'Deny');

  // Allow statements that match every action and every resource.
  const wildcardAllowStatements = allowedStatements.filter((statement) => {
    const actionPatterns = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const resourcePatterns = Array.isArray(statement.Resource)
      ? statement.Resource
      : [statement.Resource];

    return actionPatterns.includes('*') && resourcePatterns.includes('*');
  });

  // Allow statements with an exact action and either an exact or trailing-wildcard resource.
  const matchingAllowStatements = allowedStatements.filter((statement) => {
    const actionPatterns = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const resourcePatterns = Array.isArray(statement.Resource)
      ? statement.Resource
      : [statement.Resource];

    return (
      actionPatterns.includes(requestedAction) &&
      (resourcePatterns.includes(requestedResource) ||
        resourcePatterns.some(
          (resourcePattern) =>
            resourcePattern.endsWith('*') &&
            requestedResource.startsWith(resourcePattern.slice(0, -1)),
        ))
    );
  });

  // Deny statements with an exact action and exact resource.
  const exactDenyStatements = deniedStatements.filter((statement) => {
    const actionPatterns = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    const resourcePatterns = Array.isArray(statement.Resource)
      ? statement.Resource
      : [statement.Resource];

    return actionPatterns.includes(requestedAction) && resourcePatterns.includes(requestedResource);
  });

  // Deny resource prefixes for statements with an exact matching action.
  const wildcardDenyResourcePrefixes = deniedStatements
    .filter((statement) => {
      const actionPatterns = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      const resourcePatterns = Array.isArray(statement.Resource)
        ? statement.Resource
        : [statement.Resource];

      return (
        actionPatterns.includes(requestedAction) &&
        resourcePatterns.some((resourcePattern) => resourcePattern.endsWith('*'))
      );
    })
    .map((statement) => {
      const resourcePatterns = Array.isArray(statement.Resource)
        ? statement.Resource
        : [statement.Resource];

      return resourcePatterns
        .filter((resourcePattern) => resourcePattern.endsWith('*'))
        .map((resourcePattern) => resourcePattern.slice(0, -1));
    })
    .flat();

  // Action prefixes from allow statements that apply to every resource.
  const wildcardAllowActionPrefixes = allowedStatements
    .filter((statement) => {
      const actionPatterns = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      const resourcePatterns = Array.isArray(statement.Resource)
        ? statement.Resource
        : [statement.Resource];

      return (
        actionPatterns.some((actionPattern) => actionPattern.endsWith('*')) &&
        resourcePatterns.includes('*')
      );
    })
    .map((statement) => {
      const actionPatterns = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];

      return actionPatterns
        .filter((actionPattern) => actionPattern.endsWith('*'))
        .map((actionPattern) => actionPattern.slice(0, -1));
    })
    .flat();

  if (exactDenyStatements.length > 0) {
    return false;
  }

  if (
    wildcardDenyResourcePrefixes.some((resourcePrefix) =>
      requestedResource.startsWith(resourcePrefix),
    )
  ) {
    return false;
  }

  if (wildcardAllowStatements.length > 0 || matchingAllowStatements.length > 0) {
    return true;
  }

  if (
    wildcardAllowActionPrefixes.some((actionPrefix) => requestedAction.startsWith(actionPrefix))
  ) {
    return true;
  }

  return false;
}
