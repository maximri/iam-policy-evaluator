# Scenario 2: IAM Policy Evaluator (The Explicit Deny)

## The Context

Act Security focuses heavily on mapping cloud boundaries and risk. A foundational concept in AWS is that an **Explicit Deny** always overrides an **Explicit Allow**, and everything defaults to an **Implicit Deny**. To accurately map access, they need an evaluation engine that perfectly mimics AWS IAM evaluation logic.

## The Challenge

Write a local policy evaluation engine in TypeScript. The engine will parse a single AWS IAM Identity-Based Policy and evaluate whether a specific action on a specific resource is allowed or denied.

### Contract Details & Requirements

1. **Strict Typing:** Define strict TypeScript interfaces for the IAM Policy JSON structure. Do not use `any`. _Hint: According to AWS specifications, `Action` and `Resource` can be either a `string` or an array of strings (`string[]`)._
2. **Evaluation Logic Rules:**
   - **Implicit Deny:** If the requested action and resource do not match any `Allow` statement, the request is denied.
   - **Explicit Allow:** If the request matches an `Allow` statement, it is permitted (unless overridden by a Deny).
   - **Explicit Deny:** If the request matches a `Deny` statement, it is absolutely denied, overriding any Allow.
3. **Wildcard Support:** You must support the `*` wildcard in both `Action` and `Resource` definitions (e.g., `ec2:Describe*` matches `ec2:DescribeInstances`; `arn:aws:s3:::*` matches `arn:aws:s3:::random-bucket`).
4. **Scope Constraint:** You do _not_ need to implement `Condition` blocks, `NotAction`, or `NotResource` for this exercise.

## Expected Function Signature

\`\`\`typescript
function evaluateAccess(policy: IAMPolicy, requestedAction: string, requestedResource: string): boolean;
\`\`\`

## Expected Scenarios

Your engine should accurately evaluate the following test cases against `policy.json`:

1. **Broad Allow (Wildcard Action & Resource)**
   `evaluateAccess(policy, "s3:ListBucket", "arn:aws:s3:::random-bucket")`
   👉 **Expected:** `true` (Matches AllowGeneralReadOnly)

2. **Specific Allow (Exact Resource Match)**
   `evaluateAccess(policy, "s3:PutObject", "arn:aws:s3:::dev-team-sandbox/test.txt")`
   👉 **Expected:** `true` (Matches AllowDevBucketWrite)

3. **Explicit Deny Overriding Broad Allow**
   `evaluateAccess(policy, "s3:GetObject", "arn:aws:s3:::prod-customer-data/report.pdf")`
   👉 **Expected:** `false` (Caught by DenyProductionS3Access, overrides AllowGeneralReadOnly)

4. **Wildcard Overlap (Allow All vs Deny Specific)**
   `evaluateAccess(policy, "logs:CreateLogStream", "arn:aws:logs:us-east-1:123456789012:log-group:my-group")`
   👉 **Expected:** `true` (Matches AllowCloudWatchLogs)

   `evaluateAccess(policy, "logs:DeleteLogGroup", "arn:aws:logs:us-east-1:123456789012:log-group:my-group")`
   👉 **Expected:** `false` (Caught by DenyLogDeletion)

5. **Trailing Wildcard Match**
   `evaluateAccess(policy, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/dev-maxim")`
   👉 **Expected:** `true` (Matches AllowDevIAMKeyManagement)

6. **Implicit Deny (Action matches, Resource fails wildcard)**
   `evaluateAccess(policy, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/prod-admin")`
   👉 **Expected:** `false` (Implicit Deny; does not match the `dev-*` resource wildcard)

7. **Implicit Deny (Action completely missing)**
   `evaluateAccess(policy, "lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:my-func")`
   👉 **Expected:** `false` (Implicit Deny)
