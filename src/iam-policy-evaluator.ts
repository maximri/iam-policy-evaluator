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

// Resources belonging to one action pattern.
// Example:
//   Resource: "arn:aws:s3:::bucket-a/*"
//   wildcardResourcePrefixes: ["arn:aws:s3:::bucket-a/"]
interface ResourceMatcher {
  exactResources: Set<string>;
  wildcardResourcePrefixes: Set<string>;
}

// An index for one AWS service, such as "s3" or "logs".
//
// The two maps separate exact actions from actions ending in '*'.
interface ServiceActionIndex {
  // The complete operation name must match exactly.
  //
  // Example policy action: "s3:PutObject"
  // Stored as: exactActions.get("PutObject")
  // Matches: "s3:PutObject"
  // Does not match: "s3:PutObjectVersion"
  exactActions: Map<string, ResourceMatcher>;

  // The operation only needs to start with the stored prefix.
  //
  // Example policy action: "s3:List*"
  // Stored as: wildcardActionPrefixes.get("List")
  // Matches: "s3:ListBucket" and "s3:ListObjects"
  // Does not match: "s3:GetObject"
  //
  // For "logs:*", the stored prefix is "". Every operation in the
  // "logs" service starts with an empty string, so every logs action matches.
  wildcardActionPrefixes: Map<string, ResourceMatcher>;
}

// This is an IAM-shaped access index:
//   service -> action -> resources
//
// It uses meaningful IAM pieces. One index is created for Allow statements
// and another for Deny statements.
interface PolicyIndex {
  // The first lookup separates actions by service, for example "s3" from
  // "logs". Each service then has its own exact and wildcard action maps.
  actionsByService: Map<string, ServiceActionIndex>;

  // Resource matchers for statements with Action: "*".
  // Example: Action: "*", Resource: "arn:aws:s3:::bucket-a"
  // is checked here before looking for a specific service.
  allActions: ResourceMatcher;
}

function toArray<T>(value: T | T[]): T[] {
  return Array.isArray(value) ? value : [value];
}

function createResourceMatcher(): ResourceMatcher {
  return {
    exactResources: new Set(),
    wildcardResourcePrefixes: new Set(),
  };
}

function createServiceActionIndex(): ServiceActionIndex {
  return {
    exactActions: new Map(),
    wildcardActionPrefixes: new Map(),
  };
}

function createPolicyIndex(): PolicyIndex {
  return {
    actionsByService: new Map(),
    allActions: createResourceMatcher(),
  };
}

function addResourcePattern(
  resourceMatcher: ResourceMatcher,
  resourcePattern: string,
): ResourceMatcher {
  const exactResources = new Set(resourceMatcher.exactResources);
  const wildcardResourcePrefixes = new Set(resourceMatcher.wildcardResourcePrefixes);

  if (resourcePattern.endsWith('*')) {
    // A trailing resource wildcard becomes a prefix check.
    // Example: "arn:aws:iam::123:user/dev-*"
    // becomes "arn:aws:iam::123:user/dev-" and matches ".../dev-maxim".
    wildcardResourcePrefixes.add(resourcePattern.slice(0, -1));
  } else {
    exactResources.add(resourcePattern);
  }

  return { exactResources, wildcardResourcePrefixes };
}

function addResourcePatterns(
  resourceMatcher: ResourceMatcher,
  resourcePatterns: string[],
): ResourceMatcher {
  return resourcePatterns.reduce(
    (matcher, resourcePattern) => addResourcePattern(matcher, resourcePattern),
    resourceMatcher,
  );
}

function mergeResourceMatchers(
  firstMatcher: ResourceMatcher,
  secondMatcher: ResourceMatcher,
): ResourceMatcher {
  return {
    exactResources: new Set([...firstMatcher.exactResources, ...secondMatcher.exactResources]),
    wildcardResourcePrefixes: new Set([
      ...firstMatcher.wildcardResourcePrefixes,
      ...secondMatcher.wildcardResourcePrefixes,
    ]),
  };
}

function parseActionPattern(actionPattern: string): {
  serviceName: string;
  operationName: string;
  isWildcard: boolean;
} {
  const separatorIndex = actionPattern.indexOf(':');
  const operationPattern = actionPattern.slice(separatorIndex + 1);

  return {
    serviceName: actionPattern.slice(0, separatorIndex),
    operationName: operationPattern.endsWith('*')
      ? operationPattern.slice(0, -1)
      : operationPattern,
    isWildcard: operationPattern.endsWith('*'),
  };
}

function getOrCreateServiceActionIndex(
  policyIndex: PolicyIndex,
  serviceName: string,
): ServiceActionIndex {
  const existingIndex = policyIndex.actionsByService.get(serviceName);

  if (existingIndex) {
    return existingIndex;
  }

  const newIndex = createServiceActionIndex();
  policyIndex.actionsByService.set(serviceName, newIndex);
  return newIndex;
}

function addResourceMatcherToAction(
  actionMap: Map<string, ResourceMatcher>,
  operationName: string,
  resourceMatcher: ResourceMatcher,
): void {
  const existingMatcher = actionMap.get(operationName);

  actionMap.set(
    operationName,
    existingMatcher ? mergeResourceMatchers(existingMatcher, resourceMatcher) : resourceMatcher,
  );
}

function addActionPattern(
  policyIndex: PolicyIndex,
  actionPattern: string,
  resourcePatterns: string[],
): void {
  if (actionPattern === '*') {
    policyIndex.allActions = addResourcePatterns(policyIndex.allActions, resourcePatterns);
    return;
  }

  const { serviceName, operationName, isWildcard } = parseActionPattern(actionPattern);

  const serviceActionIndex = getOrCreateServiceActionIndex(policyIndex, serviceName);

  const actionMap = isWildcard
    ? serviceActionIndex.wildcardActionPrefixes
    : serviceActionIndex.exactActions;

  const resourceMatcher = addResourcePatterns(createResourceMatcher(), resourcePatterns);
  addResourceMatcherToAction(actionMap, operationName, resourceMatcher);
}

function matchesResources(resourceMatcher: ResourceMatcher, requestedResource: string): boolean {
  // First, try a complete resource match, such as "bucket-a/object.txt".
  if (resourceMatcher.exactResources.has(requestedResource)) {
    return true;
  }

  // Then try trailing-wildcard resources, such as "bucket-a/*".
  return [...resourceMatcher.wildcardResourcePrefixes].some((prefix) =>
    requestedResource.startsWith(prefix),
  );
}

function matchesExactAction(
  serviceActionIndex: ServiceActionIndex,
  operationName: string,
  requestedResource: string,
): boolean {
  const resourceMatcher = serviceActionIndex.exactActions.get(operationName);

  return resourceMatcher ? matchesResources(resourceMatcher, requestedResource) : false;
}

function matchesWildcardAction(
  serviceActionIndex: ServiceActionIndex,
  operationName: string,
  requestedResource: string,
): boolean {
  return [...serviceActionIndex.wildcardActionPrefixes].some(
    ([operationPrefix, resourceMatcher]) =>
      operationName.startsWith(operationPrefix) &&
      matchesResources(resourceMatcher, requestedResource),
  );
}

function matchesPolicyIndex(
  policyIndex: PolicyIndex,
  requestedAction: string,
  requestedResource: string,
): boolean {
  // Action: "*" is checked before service-specific actions.
  if (matchesResources(policyIndex.allActions, requestedResource)) {
    return true;
  }

  const { serviceName, operationName } = parseActionPattern(requestedAction);
  const serviceActionIndex = policyIndex.actionsByService.get(serviceName);

  if (!serviceActionIndex) {
    return false;
  }

  // First check an exact action, such as "s3:PutObject".
  if (matchesExactAction(serviceActionIndex, operationName, requestedResource)) {
    return true;
  }

  // Then check wildcard actions, such as "s3:List*".
  return matchesWildcardAction(serviceActionIndex, operationName, requestedResource);
}

function addStatementToIndex(policyIndex: PolicyIndex, statement: IAMStatement): void {
  const actionPatterns = toArray(statement.Action);
  const resourcePatterns = toArray(statement.Resource);

  for (const actionPattern of actionPatterns) {
    addActionPattern(policyIndex, actionPattern, resourcePatterns);
  }
}

export function evaluateAccess(
  policy: IAMPolicy,
  requestedAction: string,
  requestedResource: string,
): boolean {
  if (!policy.Statement) {
    return false;
  }

  const allowIndex = createPolicyIndex();
  const denyIndex = createPolicyIndex();

  // Build separate indexes for Allow and Deny statements.
  for (const statement of policy.Statement) {
    const targetIndex = statement.Effect === 'Allow' ? allowIndex : denyIndex;
    addStatementToIndex(targetIndex, statement);
  }

  // Deny wins over every matching Allow.
  if (matchesPolicyIndex(denyIndex, requestedAction, requestedResource)) {
    return false;
  }

  // No matching Allow is an implicit Deny.
  return matchesPolicyIndex(allowIndex, requestedAction, requestedResource);
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
