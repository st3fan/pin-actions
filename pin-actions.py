#!/usr/bin/env python3

#
# Pin actions [repo-path]
#

import argparse
import glob
import os
import re
from typing import Tuple

from github import Github, Repository
from github.Repository import Repository
from github.GitRelease import GitRelease
from semver import VersionInfo
import yaml



BASEVERSION = re.compile(
    r"""[vV]?
        (?P<major>0|[1-9]\d*)
        (\.
        (?P<minor>0|[1-9]\d*)
        (\.
            (?P<patch>0|[1-9]\d*)
        )?
        )?
    """,
    re.VERBOSE,
)


def coerce_version(version):
    match = BASEVERSION.search(version)
    if not match:
        return None
    ver = {
        key: 0 if value is None else value for key, value in match.groupdict().items()
    }
    return  VersionInfo(**ver)


GIT_COMMIT_RE = re.compile(r"[a-f0-9]{40}")

def get_releases(repo: Repository) -> list[GitRelease]:
    """Return a list of releases, sorted newest to oldest version"""
    releases = list(repo.get_releases())
    releases.sort(key=lambda release: coerce_version(release.tag_name), reverse=True)
    return releases


def find_latest_same_major_release(releases: list[GitRelease], version: VersionInfo) -> GitRelease|None:
    """In the given list of releases, find the most recent one that matches the major of the version"""
    for release in releases:
        if release_version := coerce_version(release.tag_name):
            if release_version.major == version.major:
                return release


def find_latest_release(gh: Github, org: str, user: str, version: str) -> Tuple[str, str]:
    """Return a tuple with commit, version and comment"""
    repo = gh.get_repo(f"{org}/{user}")

    releases = list(repo.get_releases())
    if not releases:
        raise Exception(f"Action https://github.com/{org}/{user} doesn't have any releases")

    # For common branch names we grab the commit from that branch
    if version in ("master", "main", "develop"):
        if branch := repo.get_branch(version): # TODO Throws if not exists
            return branch.commit.sha, version, "Branch"
        raise Exception(f"Could not find a release")

    # For a pinned version, we grab the latest with the same major
    if pinned_version := coerce_version(version):
        # First try to find a matching release
        if release := find_latest_same_major_release(releases, pinned_version):
            if ref := repo.get_git_ref(f"tags/{release.tag_name}"): # TODO Throws if not exists
                return ref.object.sha, release.tag_name, "Tag"
        # Look for the tag instead
        if ref := repo.get_git_ref(f"tags/{version}"): # TODO Throws if not exists
            return ref.object.sha, version, "Tag"
        # Look for a branch instead
        if branch := repo.get_branch(version): # TODO Throws if not exists
            return branch.commit.sha, version, "Branch"
        raise Exception(f"Could not find a release, tag or branch for version {version}")

    # TODO This is really rare but we can probably do something better
    raise Exception(f"Don't know what to do with version {version}")


def suggest_pinned_action(gh: Github, action: str) -> str:
    """Take an action specifier (action/foo@v123) and return the pinned version."""
    print("MOO Looking at action", action)
    full_user, version = action.split("@")
    if not full_user or not version:
        raise Exception(f"Don't know how to parse action {action}")

    org, user = full_user.split("/")
    if not org or not user:
        raise Exception(f"Don't know how to parse action user {full_user}")

    # If this is not already pinned to a commit hash, go find one
    if not GIT_COMMIT_RE.match(version):
        commit, name, comment = find_latest_release(gh, org, user, version)
        return f"{full_user}@{commit} # {name} ({comment})"


def update_workflow(gh: Github, path: str, dry_run=False):
    with open(path) as fp:
        workflow = yaml.load(fp, Loader=yaml.SafeLoader)
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                if action := step.get("uses"):
                    try:
                        if pinned_action := suggest_pinned_action(gh, action):
                            print(f"{action} -> {pinned_action}")
                    except Exception as e:
                        print("Failed", e)


def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION] [FILE]...",
        description="Pin actions to their latest release."
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version = f"{parser.prog} version 1.0.0",
    )
    parser.add_argument(
        "-d", "--dry-run", action="store_true",
    )
    parser.add_argument('files', nargs='*')
    return parser


def main() -> None:
    parser = init_argparse()
    args = parser.parse_args()

    if not (github_token := os.getenv("GITHUB_TOKEN")):
        raise SystemExit("Cannot continue without valid GITHUB_TOKEN")

    gh = Github(github_token)
    # TODO Check if token is good

    for path in args.files:
        update_workflow(gh, path, dry_run=args.dry_run)

    #print(find_latest_release(gh, "dangoslen", "changelog-enforcer", "main"))
    #print(find_latest_release(gh, "dangoslen", "changelog-enforcer", "v2"))
    #print(find_latest_release(gh, "softprops", "turnstyle", "v1"))
    #print(find_latest_release(gh, "actions", "dependency-review-action", "v2"))

    #v = coerce_version("v1")
    #print(v)

    # repo = gh.get_repo("dangoslen/changelog-enforcer")
    # releases = get_releases(repo)
    # for v in ("v2.2.3", "v2", "v1"):
    #     print(v, ":", find_latest_major_version(releases, coerce_version(v)))
    
    #return
    
    
    # ROOT="/Users/stefan.arentz/Aiven/terraform-provider-aiven"

    # for path in glob.glob(".github/workflows/*.yml", root_dir=ROOT):
        # print("MOO Looking at", path)
        # check_workflow(gh, ROOT  + "/" + path)


if __name__ == "__main__":
    main()

