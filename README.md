# codeintel-Git-Metadata-Analyzer
Analyzes a git repository's metadata (author email patterns, commit message conventions, branch naming, etc.) to identify potential anomalies indicative of malicious activity, such as impersonation or code injection, providing a risk score. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

## Install
`git clone https://github.com/ShadowGuardAI/codeintel-git-metadata-analyzer`

## Usage
`./codeintel-git-metadata-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--email_threshold`: No description provided
- `--commit_message_pattern`: Regex pattern for commit message validation.
- `--branch_name_pattern`: Regex pattern for branch name validation.
- `--output_file`: Path to output file to save analysis results.
- `--offensive_tools`: No description provided

## License
Copyright (c) ShadowGuardAI
