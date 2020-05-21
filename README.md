# aws-iam-analyser

This is a simple AWS IAM Analysis utility to gather enitre useful information from a AWS account.

## Usage

The below command uses the `default` AWS credentials configured in your system and saves the entire output in JSON format `output.json`.

```bash
python app.py analysis
```

* The output looks like below

```
{
  "AccountAliases": [
    "madhuakula-account"
  ],
  "AccountAuthorizationDetails": {
    "GroupDetailList": [
      {
        "Arn": "arn:aws:iam::123456789012:group/madhuakula",
        "AttachedManagedPolicies": [
          {
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonAPIGatewayInvokeFullAccess",
            "PolicyName": "AmazonAPIGatewayInvokeFullAccess"
          },
          {
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
            "PolicyName": "AmazonAthenaFullAccess"
          },
```

## To-Do

- [ ] Implement AWS credentials input/validation
  - [ ] Check initially for arguments passed with AWS `access_key` and `secret_access_key` and `region`
  - [ ] Else, see the OS environment variables available `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
  - [ ] Then finally check and use system aws configurations at `~/.aws/config` and `~/.aws/credentials`
- [ ] Create and implement argument parsing for each module specifically
- [ ] Many ohter...

