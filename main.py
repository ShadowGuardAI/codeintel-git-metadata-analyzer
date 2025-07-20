#!/usr/bin/env python3

import argparse
import subprocess
import re
import os
import logging
import sys
from typing import List, Dict, Any


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes git repository metadata for anomalies."
    )
    parser.add_argument(
        "repo_path",
        help="Path to the git repository.",
        type=str,
    )
    parser.add_argument(
        "--email_threshold",
        help="Threshold for email anomaly detection (default: 0.9).",
        type=float,
        default=0.9,
    )
    parser.add_argument(
        "--commit_message_pattern",
        help="Regex pattern for commit message validation.",
        type=str,
        default=r"^[A-Z][a-z]+:\s.*",
    )  # Example pattern: "Feature: Added new functionality"
    parser.add_argument(
        "--branch_name_pattern",
        help="Regex pattern for branch name validation.",
        type=str,
        default=r"^(feature|bugfix|hotfix|release)/[a-z0-9-]+$",
    )  # Example pattern: "feature/add-new-feature"
    parser.add_argument(
        "--output_file",
        help="Path to output file to save analysis results.",
        type=str,
        default="analysis_report.txt",
    )
    parser.add_argument(
        "--offensive_tools",
        action="store_true",
        help="Run offensive security tools (bandit, flake8, pylint, pyre-check).",
    )
    return parser


def run_git_command(repo_path: str, command: List[str]) -> str:
    """
    Runs a git command in the specified repository.

    Args:
        repo_path (str): Path to the git repository.
        command (List[str]): List of strings representing the git command.

    Returns:
        str: The output of the git command.

    Raises:
        subprocess.CalledProcessError: If the git command fails.
    """
    try:
        result = subprocess.run(
            ["git", "-C", repo_path] + command,
            capture_output=True,
            text=True,
            check=True,
            security=True,  # Added security check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Git command failed: {e}")
        raise


def analyze_author_emails(
    repo_path: str, threshold: float
) -> Dict[str, Any]:  # Added type hinting
    """
    Analyzes author email patterns for anomalies.

    Args:
        repo_path (str): Path to the git repository.
        threshold (float): Threshold for anomaly detection.

    Returns:
        Dict[str, Any]: A dictionary containing the analysis results.
    """
    try:
        # Retrieve all author emails and their counts
        log_output = run_git_command(
            repo_path,
            ["log", "--pretty=format:%ae", "--shortstat"],  # Modified git log command
        )
        emails = log_output.splitlines()
        if not emails:
            return {"status": "no commits found"}
        
        email_counts: Dict[str, int] = {}
        for email in emails:
          email_counts[email] = email_counts.get(email, 0) + 1
          
        total_commits = sum(email_counts.values())
        anomalies = {}
        for email, count in email_counts.items():
            frequency = count / total_commits
            if frequency < (1 - threshold):
                anomalies[email] = frequency
        
        return {"status": "success", "anomalies": anomalies}

    except subprocess.CalledProcessError as e:
        logging.error(f"Error analyzing author emails: {e}")
        return {"status": "error", "message": str(e)}


def validate_commit_messages(
    repo_path: str, pattern: str
) -> Dict[str, Any]:  # Added type hinting
    """
    Validates commit messages against a regular expression pattern.

    Args:
        repo_path (str): Path to the git repository.
        pattern (str): Regular expression pattern for commit message validation.

    Returns:
        Dict[str, Any]: A dictionary containing the analysis results.
    """
    try:
        log_output = run_git_command(repo_path, ["log", "--pretty=format:%s"])
        messages = log_output.splitlines()
        invalid_messages = []
        for message in messages:
            if not re.match(pattern, message):
                invalid_messages.append(message)
        return {"status": "success", "invalid_messages": invalid_messages}
    except subprocess.CalledProcessError as e:
        logging.error(f"Error validating commit messages: {e}")
        return {"status": "error", "message": str(e)}


def validate_branch_names(repo_path: str, pattern: str) -> Dict[str, Any]:
    """
    Validates branch names against a regular expression pattern.

    Args:
        repo_path (str): Path to the git repository.
        pattern (str): Regular expression pattern for branch name validation.

    Returns:
        Dict[str, Any]: A dictionary containing the analysis results.
    """
    try:
        branches_output = run_git_command(repo_path, ["branch", "--list"])
        branches = [
            branch.strip().replace("* ", "") for branch in branches_output.splitlines()
        ]
        invalid_branches = []
        for branch in branches:
            if not re.match(pattern, branch):
                invalid_branches.append(branch)

        return {"status": "success", "invalid_branches": invalid_branches}
    except subprocess.CalledProcessError as e:
        logging.error(f"Error validating branch names: {e}")
        return {"status": "error", "message": str(e)}


def run_offensive_tools(repo_path: str) -> Dict[str, Any]:
    """
    Runs offensive security tools (bandit, flake8, pylint, pyre-check) on the repository.

    Args:
        repo_path (str): Path to the git repository.

    Returns:
        Dict[str, Any]: A dictionary containing the output of each tool.
    """
    results: Dict[str, Any] = {}

    def run_tool(tool_name: str, command: List[str]) -> str:
        try:
            result = subprocess.run(
                command, cwd=repo_path, capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logging.error(f"{tool_name} failed: {e}")
            return f"Error: {e}"
        except FileNotFoundError:
            logging.error(f"{tool_name} is not installed.")
            return f"Error: {tool_name} is not installed. Please install it using pip."

    results["bandit"] = run_tool("bandit", ["bandit", "-r", "."])
    results["flake8"] = run_tool("flake8", ["flake8", "."])
    results["pylint"] = run_tool("pylint", ["pylint", "."])

    # Check if pyre is installed and configured
    try:
      subprocess.run(["pyre", "--version"], check=True, capture_output=True) # Checks if pyre command is available
      #Pyre needs an init configuration file. Need to check that first.
      if os.path.exists(os.path.join(repo_path, ".pyre_configuration")):
          results["pyre-check"] = run_tool("pyre-check", ["pyre", "check"])
      else:
          results["pyre-check"] = "Pyre not configured. Please run `pyre init` first"
    except FileNotFoundError:
        results["pyre-check"] = "Pyre is not installed. Please install it using pip."
    except subprocess.CalledProcessError:
        results["pyre-check"] = "Pyre failed to run. Check your configuration or dependencies."

    return results


def generate_risk_score(analysis_results: Dict[str, Any]) -> float:
    """
    Generates a risk score based on the analysis results.

    Args:
        analysis_results (Dict[str, Any]): A dictionary containing the analysis results.

    Returns:
        float: The risk score.
    """
    risk_score = 0.0

    # Author Email Anomalies
    if (
        "author_emails" in analysis_results
        and analysis_results["author_emails"]["status"] == "success"
        and analysis_results["author_emails"]["anomalies"]
    ):
        risk_score += 0.3  # Higher risk for email anomalies

    # Commit Message Validation
    if (
        "commit_messages" in analysis_results
        and analysis_results["commit_messages"]["status"] == "success"
        and analysis_results["commit_messages"]["invalid_messages"]
    ):
        risk_score += 0.2

    # Branch Name Validation
    if (
        "branch_names" in analysis_results
        and analysis_results["branch_names"]["status"] == "success"
        and analysis_results["branch_names"]["invalid_branches"]
    ):
        risk_score += 0.1

    # Offensive Tool Findings (simplified - more granular analysis needed in real-world)
    if "offensive_tools" in analysis_results:
        for tool, output in analysis_results["offensive_tools"].items():
            if "Error" not in output and output: # If no error and there is output, flag it.
                risk_score += 0.4  # Higher risk for tool findings.  Needs more sophisticated parsing in real world.

    return min(risk_score, 1.0)  # Ensure risk score is between 0 and 1


def save_analysis_report(
    analysis_results: Dict[str, Any], risk_score: float, output_file: str
) -> None:
    """
    Saves the analysis results to a file.

    Args:
        analysis_results (Dict[str, Any]): A dictionary containing the analysis results.
        risk_score (float): The calculated risk score.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            f.write("## Git Metadata Analysis Report ##\n\n")
            f.write(f"Risk Score: {risk_score:.2f}\n\n")

            f.write("### Author Email Analysis ###\n")
            if (
                "author_emails" in analysis_results
                and analysis_results["author_emails"]["status"] == "success"
            ):
                if analysis_results["author_emails"]["anomalies"]:
                    f.write("Anomalous Emails Found:\n")
                    for email, frequency in analysis_results["author_emails"][
                        "anomalies"
                    ].items():
                        f.write(f"- {email}: {frequency:.2f}\n")
                else:
                    f.write("No email anomalies found.\n")
            else:
                f.write(
                    f"Error analyzing emails: {analysis_results['author_emails']['message']}\n"
                )

            f.write("\n### Commit Message Validation ###\n")
            if (
                "commit_messages" in analysis_results
                and analysis_results["commit_messages"]["status"] == "success"
            ):
                if analysis_results["commit_messages"]["invalid_messages"]:
                    f.write("Invalid Commit Messages Found:\n")
                    for message in analysis_results["commit_messages"][
                        "invalid_messages"
                    ]:
                        f.write(f"- {message}\n")
                else:
                    f.write("All commit messages are valid.\n")
            else:
                f.write(
                    f"Error validating commit messages: {analysis_results['commit_messages']['message']}\n"
                )

            f.write("\n### Branch Name Validation ###\n")
            if (
                "branch_names" in analysis_results
                and analysis_results["branch_names"]["status"] == "success"
            ):
                if analysis_results["branch_names"]["invalid_branches"]:
                    f.write("Invalid Branch Names Found:\n")
                    for branch in analysis_results["branch_names"]["invalid_branches"]:
                        f.write(f"- {branch}\n")
                else:
                    f.write("All branch names are valid.\n")
            else:
                f.write(
                    f"Error validating branch names: {analysis_results['branch_names']['message']}\n"
                )

            f.write("\n### Offensive Security Tools Analysis ###\n")
            if "offensive_tools" in analysis_results:
                for tool, output in analysis_results["offensive_tools"].items():
                    f.write(f"\n#### {tool} ####\n")
                    f.write(output + "\n")
            else:
                f.write("Offensive tools not run.\n")

        logging.info(f"Analysis report saved to {output_file}")

    except Exception as e:
        logging.error(f"Error saving analysis report: {e}")


def main() -> None:
    """
    Main function to execute the git metadata analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.isdir(args.repo_path):
        logging.error("Invalid repository path.")
        sys.exit(1)

    try:
        analysis_results: Dict[str, Any] = {}
        analysis_results["author_emails"] = analyze_author_emails(
            args.repo_path, args.email_threshold
        )
        analysis_results["commit_messages"] = validate_commit_messages(
            args.repo_path, args.commit_message_pattern
        )
        analysis_results["branch_names"] = validate_branch_names(
            args.repo_path, args.branch_name_pattern
        )

        if args.offensive_tools:
            analysis_results["offensive_tools"] = run_offensive_tools(args.repo_path)
        else:
            analysis_results["offensive_tools"] = {}

        risk_score = generate_risk_score(analysis_results)

        save_analysis_report(analysis_results, risk_score, args.output_file)

        print(f"Analysis complete. Risk score: {risk_score:.2f}. See {args.output_file} for details.")

    except Exception as e:
        logging.exception("An unexpected error occurred:")
        sys.exit(1)


if __name__ == "__main__":
    main()