import path from 'path';
import { fileURLToPath } from 'url';
import { evaluateAccess, evaluateAccessFile } from '../src/iam-policy-evaluator';

describe('Policy Evaluator', (): void => {
  it('returns true for Broad Allow (Wildcard Action & Resource) for the sample file', (): void => {
    const testDirectory = path.dirname(fileURLToPath(import.meta.url));
    const fixturePath = path.join(testDirectory, 'fixtures', 'policy.json');

    expect(evaluateAccessFile(fixturePath, 's3:ListBucket', 'arn:aws:s3:::random-bucket')).toBe(
      true,
    );
  });

  describe(evaluateAccess, (): void => {
    it('evaluateAccess should return true for Broad Allow (Wildcard Action & Resource)', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
              },
            ],
          },
          's3:ListBucket',
          'arn:aws:s3:::random-bucket',
        ),
      ).toBe(true);
    });

    it('evaluateAccess should return true for Specific Allow (Exact Resource Match)', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:PutObject',
                Resource: 'arn:aws:s3:::dev-team-sandbox/test.txt',
              },
            ],
          },
          's3:PutObject',
          'arn:aws:s3:::dev-team-sandbox/test.txt',
        ),
      ).toBe(true);
    });

    it('evaluateAccess should return false for Explicit Deny Overriding Broad Allow with Wildcard Resource', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
              },
              {
                Effect: 'Deny',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::prod-customer-data/*',
              },
            ],
          },
          's3:GetObject',
          'arn:aws:s3:::prod-customer-data/report.pdf',
        ),
      ).toBe(false);
    });

    it('evaluateAccess should return true for Explicit Deny Overriding Broad Allow', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
              },
              {
                Effect: 'Deny',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::prod-customer-data/*',
              },
            ],
          },
          's3:SetObject',
          'arn:aws:s3:::prod-customer-data/report.pdf',
        ),
      ).toBe(true);
    });

    it('evaluateAccess should return true for Wildcard Overlap (Allow All vs Deny Specific)', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'logs:*',
                Resource: '*',
              },
              {
                Effect: 'Deny',
                Action: 'logs:DeleteLogGroup',
                Resource: '*',
              },
            ],
          },
          'logs:CreateLogStream',
          'arn:aws:logs:us-east-1:123456789012:log-group:my-group',
        ),
      ).toBe(true);

      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'logs:*',
                Resource: '*',
              },
              {
                Effect: 'Deny',
                Action: 'logs:DeleteLogGroup',
                Resource: '*',
              },
            ],
          },
          'logs:DeleteLogGroup',
          'arn:aws:logs:us-east-1:123456789012:log-group:my-group',
        ),
      ).toBe(false);
    });

    it('evaluateAccess should return true for Trailing Wildcard Match', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'iam:CreateAccessKey',
                Resource: 'arn:aws:iam::123456789012:user/dev-*',
              },
            ],
          },
          'iam:CreateAccessKey',
          'arn:aws:iam::123456789012:user/dev-maxim',
        ),
      ).toBe(true);
    });

    it('evaluateAccess should return false for Implicit Deny (Action matches, Resource fails wildcard)', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'iam:CreateAccessKey',
                Resource: 'arn:aws:iam::123456789012:user/dev-*',
              },
            ],
          },
          'iam:CreateAccessKey',
          'arn:aws:iam::123456789012:user/prod-admin',
        ),
      ).toBe(false);
    });

    it('evaluateAccess should return false for Implicit Deny (Action completely missing)', (): void => {
      expect(
        evaluateAccess(
          {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 'iam:CreateAccessKey',
                Resource: 'arn:aws::iam::123456789012:user/dev-*',
              },
            ],
          },
          'lambda:InvokeFunction',
          'arn:aws:lambda:us-east-1:123456789012:function:my-func',
        ),
      ).toBe(false);
    });
  });
});
